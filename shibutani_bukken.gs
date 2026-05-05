// ══════════════════════════════════════════════════
//  CLH 物件マスター API（Clavis 合鍵注文システム）
//  デプロイ: ウェブアプリ → アクセス: 全員
//  参照: key-order-app の GAS/コード.js と同水準のセキュリティ強化
//
//  エンドポイント:
//    GET  ?pass=XXXXXX                          — PASSコード照合（物件情報取得）
//      [optional] &apiKey=...                   — Worker 経由なら必須
//      [optional] &ts=<unix_ms>&hmac=<hex>      — Worker HMAC 署名検証
//    POST { action: 'audit_verify' }            — 監査ログ整合性検証
//    POST { action: 'log_worker_error', ... }   — Worker エラーログ受信
//    POST { action: 'honeypot_hit', ... }       — ハニーポット監査ログ
//
//  スクリプトプロパティ（設定必須）:
//    ORDER_API_KEY       — Worker と共有する API キー（Worker 経由を保証）
//    WORKER_HMAC_KEY     — Worker 生成 HMAC 検証用鍵（未設定なら後方互換）
//    WORKER_LOG_KEY      — Worker エラーログ受信用認証キー
//    AUDIT_LOG_SHEET_ID  — 監査ログ保存先スプシ（任意、未設定なら本スプシに audit_log シート自動作成）
//    ALLOWED_PASS_PREFIX — PASS コード許容プレフィックス（例 '[0-9]{6}'、空なら全許可）
// ══════════════════════════════════════════════════
var SHEET_ID = '1YxytV8UuRMn3wvi4reuHyT9sv79sKXOONdOj6pK8HhI';
var AUDIT_SHEET_NAME = 'audit_log';

// ────────────────────────────────────────────────────
// ユーティリティ（key-order-app と同実装）
// ────────────────────────────────────────────────────
function getProp(key)       { return PropertiesService.getScriptProperties().getProperty(key) || ''; }
function setProp(key, val)  { PropertiesService.getScriptProperties().setProperty(key, String(val)); }
function delProp(key)       { PropertiesService.getScriptProperties().deleteProperty(key); }

// JST タイムスタンプ
function jstNow() {
  return Utilities.formatDate(new Date(), 'Asia/Tokyo', "yyyy-MM-dd'T'HH:mm:ssXXX");
}

// SHA-256 ハッシュ（hex 文字列）
function sha256_gas(message) {
  var bytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256, String(message), Utilities.Charset.UTF_8
  );
  return bytes.map(function(b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
}

// P1-2 相当: Formula Injection 対策
function sanitizeFormula_(value) {
  if (value == null) return value;
  var s = String(value);
  if (s.length === 0) return s;
  if (/^[=+\-@]/.test(s)) return "'" + s;
  return s;
}

// G-6 相当: JSON.parse 安全ヘルパー
function safeJsonParse_(str, fallback) {
  if (str == null || str === '') return fallback;
  try { return JSON.parse(str); } catch(_) { return fallback; }
}

// S-1(b) 相当: 定数時間比較
function constantTimeEqual_(a, b) {
  try {
    var ha = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(a || ''));
    var hb = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(b || ''));
    var acc = 0;
    for (var i = 0; i < ha.length; i++) acc |= (ha[i] ^ hb[i]);
    return acc === 0;
  } catch(_) { return false; }
}

// M-3 相当: PII マスク（電話・メールのみ対象）
function maskPII(text) {
  if (!text) return '';
  var s = String(text);
  s = s.replace(/(\d{2,4})-?\d{3,4}-?(\d{4})/g, '***-****-****');
  s = s.replace(/[a-zA-Z0-9][a-zA-Z0-9._+\-]*@[a-zA-Z0-9\-]+((?:\.[a-zA-Z0-9\-]+)+)/g, function(m, tldPart) {
    var lastDot = tldPart.lastIndexOf('.');
    var finalTld = lastDot >= 0 ? tldPart.substring(lastDot) : tldPart;
    return '****@***' + finalTld;
  });
  return s;
}

// メールヘッダインジェクション対策
function sanitizeMailField_(s) {
  return String(s == null ? '' : s).replace(/[\r\n\u0085\u2028\u2029]/g, ' ');
}

// S1-M6 相当: Worker 発行 HMAC 署名の検証
//   payload: action + '|' + id + '|' + timestamp
//   ±5 分の時刻窓内で constant-time 検証。
//   WORKER_HMAC_KEY 未設定時は { ok:true, skipped:true } で後方互換維持。
function verifyWorkerHmac_(action, id, timestamp, providedHmac) {
  try {
    var hmacKey = getProp('WORKER_HMAC_KEY');
    if (!hmacKey) return { ok: true, skipped: true };
    if (!providedHmac || !timestamp) return { ok: false, reason: 'missing_hmac_or_timestamp' };
    var ts = parseInt(timestamp, 10) || 0;
    var now = Date.now();
    if (Math.abs(now - ts) > 5 * 60 * 1000) {
      return { ok: false, reason: 'timestamp_out_of_window' };
    }
    var msg = String(action) + '|' + String(id) + '|' + String(timestamp);
    var sigBytes = Utilities.computeHmacSha256Signature(msg, hmacKey);
    var expected = sigBytes.map(function(b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
    if (!constantTimeEqual_(expected, String(providedHmac))) {
      return { ok: false, reason: 'hmac_mismatch' };
    }
    return { ok: true, skipped: false };
  } catch(e) {
    return { ok: false, reason: 'verify_error' };
  }
}

// ────────────────────────────────────────────────────
// ブルートフォース対策（GAS in-memory + CacheService）
//   PASS コード 6 桁 → 100 万通り。1 分 5 試行/IP で全量 380 日。
//   Worker 経由（Origin/Referer 検証 + IP 単位レート制限 30 qpm）後のため
//   GAS 側は補助的な失敗回数トラッキングのみ。
// ────────────────────────────────────────────────────
var PASS_FAIL_CACHE_PREFIX = 'pass_fail_';
var PASS_FAIL_IP_CACHE_PREFIX = 'pass_fail_ip_';
var PASS_FAIL_MAX = 30;                 // 1 時間 30 回まで（pass-key 単位）
var PASS_FAIL_IP_MAX = 50;              // 1 時間 50 回まで（IP 単位、2026-05-03 hotfix）
var PASS_FAIL_WINDOW_SEC = 60 * 60;     // 1 時間
function checkPassBruteforce_(passKey, clientIp) {
  try {
    var cache = CacheService.getScriptCache();
    var cacheKey = PASS_FAIL_CACHE_PREFIX + sha256_gas(String(passKey)).slice(0, 16);
    var ipKey = clientIp ? (PASS_FAIL_IP_CACHE_PREFIX + sha256_gas(String(clientIp)).slice(0, 16)) : null;
    var cur = parseInt(cache.get(cacheKey) || '0', 10) || 0;
    var ipCur = ipKey ? (parseInt(cache.get(ipKey) || '0', 10) || 0) : 0;
    // 2026-05-03 hotfix: pass-key 単位の制限のみだと違う pass を試行することで実質無制限。IP 単位の上限を追加
    if (cur >= PASS_FAIL_MAX || ipCur >= PASS_FAIL_IP_MAX) {
      return { blocked: true, count: cur, ipCount: ipCur };
    }
    return { blocked: false, count: cur, ipCount: ipCur, cacheKey: cacheKey, ipCacheKey: ipKey };
  } catch(_) {
    return { blocked: false, count: 0 };
  }
}
function recordPassFailure_(state) {
  try {
    if (!state) return;
    var cache = CacheService.getScriptCache();
    if (state.cacheKey) cache.put(state.cacheKey, String((state.count || 0) + 1), PASS_FAIL_WINDOW_SEC);
    if (state.ipCacheKey) cache.put(state.ipCacheKey, String((state.ipCount || 0) + 1), PASS_FAIL_WINDOW_SEC);
  } catch(_) {}
}

// ────────────────────────────────────────────────────
// 監査ログ（auditLog + ハッシュチェーン）
//   各行: [timestamp, action, actorEmail, actorRole, targetId, maskedDetail, prevHash, currentHash]
//   currentHash = SHA-256(timestamp | action | actorEmail | actorRole | targetId | maskedDetail | prevHash)
//   WORKER_LOG_KEY 未設定 + AUDIT_LOG_SHEET_ID 未設定でも本スプシに audit_log シート自動作成
// ────────────────────────────────────────────────────
function getAuditLogSheet_() {
  try {
    var targetId = getProp('AUDIT_LOG_SHEET_ID') || SHEET_ID;
    var ss = SpreadsheetApp.openById(targetId);
    var sh = ss.getSheetByName(AUDIT_SHEET_NAME);
    if (!sh) {
      sh = ss.insertSheet(AUDIT_SHEET_NAME);
      sh.appendRow(['timestamp', 'action', 'actorEmail', 'actorRole', 'targetId', 'maskedDetail', 'prevHash', 'currentHash']);
      sh.setFrozenRows(1);
    }
    return sh;
  } catch(e) {
    console.error('getAuditLogSheet_ error:', e && e.message);
    return null;
  }
}

function auditLog(action, actor, detail) {
  // 2026-05-05: LockService で並行書き込み時のハッシュチェーン破損を防止
  var __auditLock = LockService.getScriptLock();
  var __auditLockAcquired = false;
  try { __auditLockAcquired = __auditLock.tryLock(5000); } catch(_e) { __auditLockAcquired = false; }
  if (!__auditLockAcquired) {
    console.error('shibutani auditLog: lock timeout, action=' + action);
    return;
  }
  try {
    var sh = getAuditLogSheet_();
    if (!sh) return;
    var actorEmail = '', actorRole = actor || '';
    if (actor && String(actor).indexOf('@') !== -1) {
      actorEmail = String(actor);
      actorRole = '';
    }
    // ログインジェクション防止: CR/LF / パイプ文字をスペース化
    var maskedDetail = maskPII(detail || '')
      .replace(/[\r\n\u0085\u2028\u2029]/g, ' ')
      .replace(/\|/g, ' ')
      .slice(0, 500);
    var targetId = '';
    var idMatch = String(detail || '').match(/^(?:id=|pass=)?([a-z0-9]{4,})/i);
    if (idMatch) targetId = idMatch[1].slice(0, 40);
    var ts = jstNow();

    // prevHash 取得
    var prevHash = '';
    try {
      var lastRow = sh.getLastRow();
      if (lastRow >= 2) {
        var lastCol = sh.getLastColumn();
        if (lastCol >= 8) prevHash = String(sh.getRange(lastRow, 8).getValue() || '');
      }
    } catch(_) {}

    var currentHash = sha256_gas(
      ts + '|' + action + '|' + actorEmail + '|' + actorRole + '|' + targetId + '|' + maskedDetail + '|' + prevHash
    );
    sh.appendRow([ts, action, actorEmail, actorRole, targetId, maskedDetail, prevHash, currentHash]);
  } catch(e) {
    console.error('auditLog error:', e && e.message);
  } finally {
    try { __auditLock.releaseLock(); } catch(_re) {}
  }
}

// H-3 相当: 監査ログ改ざん検知
function verifyAuditLogIntegrity() {
  try {
    var sh = getAuditLogSheet_();
    if (!sh) return { ok: false, totalRows: 0, tamperedRows: [], message: 'audit_log シートが見つかりません' };
    var lastRow = sh.getLastRow();
    if (lastRow < 2) return { ok: true, totalRows: 0, tamperedRows: [], message: 'ログ未記録' };
    var lastCol = sh.getLastColumn();
    if (lastCol < 8) return { ok: false, totalRows: lastRow - 1, tamperedRows: [], message: 'prevHash/currentHash 列が存在しません' };
    var values = sh.getRange(2, 1, lastRow - 1, 8).getValues();
    var tampered = [];
    var expectedPrev = '';
    for (var i = 0; i < values.length; i++) {
      var row = values[i];
      var ts = String(row[0] || '');
      var action = String(row[1] || '');
      var actorEmail = String(row[2] || '');
      var actorRole = String(row[3] || '');
      var targetId = String(row[4] || '');
      var maskedDetail = String(row[5] || '');
      var storedPrev = String(row[6] || '');
      var storedCurrent = String(row[7] || '');
      if (storedPrev !== expectedPrev) {
        tampered.push(i + 2);
      } else {
        var calc = sha256_gas(ts + '|' + action + '|' + actorEmail + '|' + actorRole + '|' + targetId + '|' + maskedDetail + '|' + storedPrev);
        if (calc !== storedCurrent) tampered.push(i + 2);
      }
      expectedPrev = storedCurrent;
    }
    var totalRows = values.length;
    return {
      ok: tampered.length === 0,
      totalRows: totalRows,
      tamperedRows: tampered,
      message: tampered.length === 0
        ? ('全 ' + totalRows + ' 行の整合性 OK')
        : ('改ざん検知: ' + tampered.length + ' 行')
    };
  } catch(err) {
    return { ok: false, totalRows: 0, tamperedRows: [], message: '検証エラー: ' + (err && err.message ? err.message : String(err)) };
  }
}

// セキュリティアラート通知（デバウンス付き）
function sendSecurityAlertMail_(alertType, subject, body) {
  try {
    var recipient = getProp('SECURITY_ALERT_EMAIL') || 'maeda.clh@gmail.com';
    var bucketKey = 'alert_' + alertType + '_' + Utilities.formatDate(new Date(), 'Asia/Tokyo', 'yyyyMMddHH');
    if (getProp(bucketKey)) return;
    setProp(bucketKey, '1');
    MailApp.sendEmail({
      to: recipient,
      subject: sanitizeMailField_('[Clavis セキュリティ] ' + subject),
      body: body + '\n\n---\nClavis 合鍵注文システムの自動アラートです。\n発生時刻: ' + jstNow(),
    });
  } catch(e) {
    console.error('sendSecurityAlertMail_ failed:', e && e.message);
  }
}

// S1-#16 相当: 日次自動検証（setupVerifyAuditLogTrigger で 03:00 JST トリガー登録）
function verifyAuditLogDaily() {
  try {
    var result = verifyAuditLogIntegrity();
    if (result && result.tamperedRows && result.tamperedRows.length > 0) {
      var subject = '⚠️ 監査ログ改ざん検知 (' + result.tamperedRows.length + '行)';
      var body = 'Clavis 物件マスター監査ログのハッシュチェーン検証で改ざんが検出されました。\n\n' +
                 '改ざん行数: ' + result.tamperedRows.length + '\n' +
                 '検査行数: ' + (result.totalRows || 0) + '\n\n' +
                 '対象行（先頭10件）: ' + result.tamperedRows.slice(0, 10).join(', ') + '\n\n' +
                 '対応: 監査ログスプシを確認してください。';
      sendSecurityAlertMail_('tamper_detected', subject, body);
      auditLog('verify_audit_log_daily_tampered', 'system', 'count=' + result.tamperedRows.length);
    } else {
      auditLog('verify_audit_log_daily_ok', 'system', 'rows=' + (result && result.totalRows || 0));
    }
  } catch(e) {
    auditLog('verify_audit_log_daily_error', 'system', String(e && e.message).slice(0, 200));
  }
}

function setupVerifyAuditLogTrigger() {
  var existing = ScriptApp.getProjectTriggers();
  existing.forEach(function(t) {
    if (t.getHandlerFunction() === 'verifyAuditLogDaily') ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('verifyAuditLogDaily').timeBased().atHour(3).everyDays(1).create();
  return 'verifyAuditLogDaily トリガー登録完了（毎日 03:00 JST）';
}

// ────────────────────────────────────────────────────
// Worker エラーログ受信（key-order-app の logWorkerError と同じプロトコル）
// ────────────────────────────────────────────────────
var WORKER_ERROR_TYPES_ = {
  csrf_block: true,
  missing_ip: true,
  rate_limit: true,
  gas_timeout: true,
  worker_exception: true,
  origin_block: true,
  auth_fail: true,
};
function logWorkerError(data) {
  try {
    var expectedKey = getProp('WORKER_LOG_KEY');
    if (!expectedKey) return;
    var providedKey = String((data && data.workerLogKey) || '');
    if (!constantTimeEqual_(expectedKey, providedKey)) return;
    var errorType = String((data && data.errorType) || '').slice(0, 40);
    if (!WORKER_ERROR_TYPES_[errorType]) return;
    var pathname   = String((data && data.pathname)   || '').replace(/[\r\n]/g, ' ').slice(0, 120);
    var method     = String((data && data.method)     || '').replace(/[\r\n]/g, ' ').slice(0, 10);
    var httpStatus = parseInt((data && data.httpStatus), 10) || 0;
    var ip         = String((data && data.ip)         || '').replace(/[\r\n]/g, ' ').slice(0, 64);
    var ua         = String((data && data.userAgent)  || '').replace(/[\r\n]/g, ' ').slice(0, 100);
    var detail     = String((data && data.detail)     || '').replace(/[\r\n]/g, ' ').slice(0, 200);
    var logDetail = 'path=' + pathname + ' method=' + method + ' status=' + httpStatus +
                    ' ip=' + ip + ' ua=' + ua + ' detail=' + detail;
    auditLog('worker_' + errorType, 'worker', logDetail);
  } catch(_) {}
}

// ハニーポット監査（Worker がハニーポットヒットを転送してきた場合）
function honeypotHit_(data) {
  try {
    var apiKey = getProp('ORDER_API_KEY');
    if (apiKey && !constantTimeEqual_(apiKey, String((data && data.apiKey) || ''))) return;
    var ip = String((data && data.ip) || '').replace(/[\r\n]/g, ' ').slice(0, 64);
    var path = String((data && data.path) || '').replace(/[\r\n]/g, ' ').slice(0, 120);
    var method = String((data && data.method) || '').replace(/[\r\n]/g, ' ').slice(0, 10);
    var ua = String((data && data.ua) || '').replace(/[\r\n]/g, ' ').slice(0, 200);
    auditLog('honeypot_hit', 'worker', 'ip=' + ip + ' path=' + path + ' method=' + method + ' ua=' + ua);
  } catch(_) {}
}

// ────────────────────────────────────────────────────
// JSON レスポンス（セキュリティヘッダは GAS では設定不可、Content-Type のみ制御）
// ────────────────────────────────────────────────────
function jsonResponse(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

// ────────────────────────────────────────────────────
// GET: 物件マスター照合
//   認証方式（3 段階、後方互換性維持）:
//     1) ORDER_API_KEY 未設定 + WORKER_HMAC_KEY 未設定 → 認証なし（初期デプロイ互換）
//     2) ORDER_API_KEY 設定あり → apiKey パラメータ必須（定数時間比較）
//     3) WORKER_HMAC_KEY 設定あり → apiKey + ts + hmac 必須（action='get_property' を想定）
//   PASS コード入力はフォーマット検証 + ブルートフォース対策（CacheService ベース）
// ────────────────────────────────────────────────────
function doGet(e) {
  var pass = '';
  try {
    var rawPass = (e && e.parameter && e.parameter.pass) || '';
    pass = String(rawPass).trim();
  } catch(_) {}

  // 入力バリデーション: 4〜12 桁の英数字のみ（PASS コードは数字6桁だが念のため幅を持たせる）
  if (!pass) {
    auditLog('get_property_missing_pass', 'public', 'ip=unknown');
    return jsonResponse({ status: 'error', message: 'PASSコードが指定されていません' });
  }
  if (!/^[a-zA-Z0-9]{4,12}$/.test(pass)) {
    auditLog('get_property_invalid_format', 'public', 'pass_len=' + pass.length);
    return jsonResponse({ status: 'error', message: 'PASSコードの形式が不正です' });
  }

  // 認証検証（ORDER_API_KEY 設定時は必須）
  var expectedApiKey = getProp('ORDER_API_KEY');
  if (expectedApiKey) {
    var providedKey = String((e && e.parameter && e.parameter.apiKey) || '');
    if (!constantTimeEqual_(expectedApiKey, providedKey)) {
      auditLog('get_property_auth_fail', 'public', 'reason=apikey_mismatch');
      return jsonResponse({ status: 'error', message: '認証エラー' });
    }
  }

  // HMAC 検証（WORKER_HMAC_KEY 設定時のみ）
  var hmacKey = getProp('WORKER_HMAC_KEY');
  if (hmacKey) {
    var ts = (e && e.parameter && e.parameter.ts) || '';
    var hmac = (e && e.parameter && e.parameter.hmac) || '';
    var v = verifyWorkerHmac_('get_property', pass, ts, hmac);
    if (!v.ok) {
      auditLog('get_property_auth_fail', 'public', 'reason=hmac_' + v.reason);
      return jsonResponse({ status: 'error', message: '認証エラー' });
    }
  }

  // ブルートフォース対策（PASS 試行回数）
  // 2026-05-03 hotfix: IP 単位カウンタも併用（worker 経由で渡される clientIp ヘッダ or fp）
  var clientIp = (e && e.parameter && (e.parameter.clientIp || e.parameter.fp)) || '';
  var bruteState = checkPassBruteforce_(pass, clientIp);
  if (bruteState.blocked) {
    auditLog('get_property_rate_limit', 'public', 'pass_hash=' + sha256_gas(pass).slice(0, 8));
    return jsonResponse({ status: 'error', message: 'リクエストが多すぎます。しばらく待ってから再試行してください。' });
  }

  try {
    var ss    = SpreadsheetApp.openById(SHEET_ID);
    var sheet = ss.getSheetByName('物件マスター');
    if (!sheet) throw new Error('物件マスターシートが見つかりません');

    var data    = sheet.getDataRange().getValues();
    var headers = data[0];

    for (var i = 1; i < data.length; i++) {
      var row = data[i];
      if (String(row[0]).trim() === String(pass)) {
        var obj = {};
        headers.forEach(function(h, idx) {
          obj[h] = row[idx];
        });
        auditLog('get_property_ok', 'public', 'pass_hash=' + sha256_gas(pass).slice(0, 8));
        return jsonResponse({ status: 'ok', property: obj });
      }
    }

    recordPassFailure_(bruteState);
    auditLog('get_property_not_found', 'public', 'pass_hash=' + sha256_gas(pass).slice(0, 8));
    return jsonResponse({ status: 'error', message: '入力されたPASSコードに一致する物件が見つかりません' });
  } catch (err) {
    auditLog('get_property_error', 'public', 'err=' + String(err && err.message).slice(0, 100));
    // 内部エラーの詳細はクライアントに返さない
    return jsonResponse({ status: 'error', message: 'サーバーエラー' });
  }
}

// ────────────────────────────────────────────────────
// POST: Worker からのシステム系通信専用
//   action: log_worker_error / honeypot_hit / audit_verify
//   単なる物件照会は GET のみ（公開窓口を分離）
// ────────────────────────────────────────────────────
function doPost(e) {
  try {
    var raw = (e && e.postData && e.postData.contents) || '';
    var body = safeJsonParse_(raw, null);
    if (!body || typeof body !== 'object') {
      return jsonResponse({ status: 'error', message: 'Invalid JSON' });
    }

    // ボディサイズ上限（9KB、key-order-app と同水準）
    if (raw.length > 9 * 1024) {
      return jsonResponse({ status: 'error', message: 'Payload too large' });
    }

    var action = String(body.action || '').slice(0, 40);

    // Worker エラーログ受信
    if (action === 'log_worker_error') {
      logWorkerError(body);
      return jsonResponse({ status: 'ok' });
    }

    // ハニーポットヒット受信
    if (action === 'honeypot_hit') {
      honeypotHit_(body);
      return jsonResponse({ status: 'ok' });
    }

    // 監査ログ整合性検証（Worker からのヘルスチェック用、ORDER_API_KEY 必須）
    if (action === 'audit_verify') {
      var apiKey = getProp('ORDER_API_KEY');
      if (!apiKey || !constantTimeEqual_(apiKey, String(body.apiKey || ''))) {
        return jsonResponse({ status: 'error', message: '認証エラー' });
      }
      var result = verifyAuditLogIntegrity();
      return jsonResponse({ status: 'ok', result: result });
    }

    // [v3.17 H-12 (2026-04-27 JST)] 物件マスタ検索 API（bukken-search アプリ用）
    //   ORDER_API_KEY 必須 + Worker HMAC 検証 + 内部認証（business_token）
    //   フリーワード検索 + フィールド別検索 + ページング
    if (action === 'search_bukken') {
      // ① ORDER_API_KEY 必須
      var apiKey2 = getProp('ORDER_API_KEY');
      if (!apiKey2 || !constantTimeEqual_(apiKey2, String(body.apiKey || ''))) {
        auditLog('search_bukken_auth_fail', body.userEmail || '', 'reason=apikey_mismatch');
        return jsonResponse({ status: 'error', message: '認証エラー' });
      }
      // ② Worker HMAC 検証（WORKER_HMAC_KEY 設定時のみ）
      var hmacKey2 = getProp('WORKER_HMAC_KEY');
      if (hmacKey2) {
        var hv = verifyWorkerHmac_('search_bukken', String(body.userEmail || ''), body.ts || '', body.hmac || '');
        if (!hv.ok) {
          auditLog('search_bukken_auth_fail', body.userEmail || '', 'reason=hmac_' + hv.reason);
          return jsonResponse({ status: 'error', message: '認証エラー' });
        }
      }
      return jsonResponse(searchBukken_(body));
    }

    return jsonResponse({ status: 'error', message: 'unknown_action' });
  } catch(err) {
    return jsonResponse({ status: 'error', message: 'サーバーエラー' });
  }
}

// ══════════════════════════════════════════════════
// [v3.17 H-12] 物件マスタ検索（bukken-search アプリ用）
//
//  シート名: 「物件マスタ全件」（既存「物件マスター」=Clavis 注文用と区別）
//  必須列: buken_id, 物件名, 仮称, 住所, 分類, 住戸数, 事業主, 管理会社, 竣工年,
//          竣工月, 共用部1, 共用部2, 専有部1, 専有部2, 専有部3, 専有部opt1,
//          専有部opt2, 専有部opt3, ハンドル, ハンドルカラー, シリンダー区分,
//          錠ケース, 装置加算額有無, シリンダーカラー, 扉厚, ピッチ, 備芯,
//          官民仕様, ロック数, キーチェンジ, 塩害地加算
//
//  入力: { q?: string, mansion?: string, year?: string, kyouyou?: string,
//          senyuu?: string, bunrui?: string, limit?: number, offset?: number }
//  出力: { status: 'ok', total: number, results: Object[] }
//
//  キャッシュ: 物件マスタは更新頻度低のため CacheService で 5 分キャッシュ
// ══════════════════════════════════════════════════
var BUKKEN_SHEET_NAME = '物件マスタ全件';
var BUKKEN_CACHE_KEY  = 'bukken_master_cache_v1';
var BUKKEN_CACHE_TTL  = 5 * 60; // 5 分

function searchBukken_(body) {
  try {
    // 入力サニタイズ
    var q       = String(body.q       || '').trim().toLowerCase();
    var mansion = String(body.mansion || '').trim().toLowerCase();
    var year    = String(body.year    || '').trim();
    var kyouyou = String(body.kyouyou || '').trim();
    var senyuu  = String(body.senyuu  || '').trim();
    var bunrui  = String(body.bunrui  || '').trim();
    var limit   = Math.min(Math.max(parseInt(body.limit  || '40', 10) || 40, 1), 100);
    var offset  = Math.max(parseInt(body.offset || '0',   10) || 0, 0);

    // フィルタ後の全件は最大 1,000 件まで（過大量レスポンス防止）
    var MAX_FILTERED = 1000;

    // 物件マスタを取得（キャッシュ優先）
    var allRows = __loadBukkenMaster_();
    if (!allRows || allRows.length === 0) {
      return { status: 'error', message: '物件マスタが空または未投入です' };
    }

    // フィルタリング
    var filtered = allRows.filter(function(p) {
      // フリーワード q: 物件名 / 仮称 / 住所 / 事業主 / 管理会社 を対象
      if (q) {
        var hay = ((p['物件名'] || '') + '|' + (p['仮称'] || '') + '|' +
                   (p['住所'] || '') + '|' + (p['事業主'] || '') + '|' +
                   (p['管理会社'] || '')).toLowerCase();
        if (hay.indexOf(q) < 0) return false;
      }
      if (mansion && String(p['物件名'] || '').toLowerCase().indexOf(mansion) < 0) return false;
      // 2026-05-03 hotfix: year は 'YYYY-YYYY' のレンジ文字列。indexOf では一致しないバグ修正
      if (year) {
        var yp = String(p['竣工年'] || '').match(/(\d{4})/);
        var yn = yp ? Number(yp[1]) : NaN;
        if (year.indexOf('-') !== -1) {
          var yr = year.split('-');
          var yFrom = Number(yr[0]);
          var yTo   = Number(yr[1]);
          if (!isFinite(yn) || yn < yFrom || yn > yTo) return false;
        } else if (String(p['竣工年'] || '').indexOf(year) < 0) {
          return false;
        }
      }
      if (kyouyou && String(p['共用部1'] || '') !== kyouyou && String(p['共用部2'] || '') !== kyouyou) return false;
      if (senyuu && String(p['専有部1'] || '') !== senyuu && String(p['専有部2'] || '') !== senyuu && String(p['専有部3'] || '') !== senyuu) return false;
      if (bunrui && String(p['分類'] || '') !== bunrui) return false;
      return true;
    });

    // 2026-05-03 hotfix: sort パラメータをサーバー側で処理（フロントが送信していたが GAS は無視していた）
    var sortKey = String(body.sort || '').trim();
    if (sortKey) {
      var _cmp = function(a, b, key, asc) {
        var av = a[key] || '', bv = b[key] || '';
        if (typeof av === 'number' && typeof bv === 'number') return asc ? av - bv : bv - av;
        return asc ? String(av).localeCompare(String(bv), 'ja') : String(bv).localeCompare(String(av), 'ja');
      };
      // 2026-05-05 fix: schema 実フィールド名と一致させる ('物件id' → 'buken_id', '戸数' → '住戸数')
      switch (sortKey) {
        case 'id_desc':    filtered.sort(function(a,b){ return _cmp(a,b,'buken_id', false); }); break;
        case 'id_asc':     filtered.sort(function(a,b){ return _cmp(a,b,'buken_id', true);  }); break;
        case 'name_asc':   filtered.sort(function(a,b){ return _cmp(a,b,'物件名',   true);  }); break;
        case 'units_desc': filtered.sort(function(a,b){ return _cmp(a,b,'住戸数',   false); }); break;
        case 'year_desc':  filtered.sort(function(a,b){ return _cmp(a,b,'竣工年',   false); }); break;
        case 'year_asc':   filtered.sort(function(a,b){ return _cmp(a,b,'竣工年',   true);  }); break;
      }
    }

    var total = filtered.length;
    if (total > MAX_FILTERED) {
      filtered = filtered.slice(0, MAX_FILTERED);
    }
    var pageResults = filtered.slice(offset, offset + limit);

    auditLog('search_bukken_ok', body.userEmail || '', 'q=' + q.slice(0, 30) + ' total=' + total + ' limit=' + limit);

    return { status: 'ok', total: total, returned: pageResults.length, results: pageResults };
  } catch(err) {
    auditLog('search_bukken_error', body.userEmail || '', 'err=' + String(err && err.message).slice(0, 100));
    return { status: 'error', message: 'サーバーエラー' };
  }
}

// 物件マスタの全件取得（CacheService で 5 分キャッシュ）
//   キャッシュサイズ上限 100KB のため、6,686 件 × 30 列 ≒ 5MB は CacheService に入らない
//   → 単純な「シート読込→オブジェクト配列化」で実装。スプシ読込は ~1-2 秒、許容範囲
function __loadBukkenMaster_() {
  try {
    var ss = SpreadsheetApp.openById(SHEET_ID);
    var sh = ss.getSheetByName(BUKKEN_SHEET_NAME);
    if (!sh) return [];
    var lastRow = sh.getLastRow();
    var lastCol = sh.getLastColumn();
    if (lastRow < 2) return [];
    var values = sh.getRange(1, 1, lastRow, lastCol).getValues();
    var headers = values[0];
    var rows = [];
    for (var i = 1; i < values.length; i++) {
      var obj = {};
      for (var j = 0; j < headers.length; j++) {
        obj[String(headers[j])] = values[i][j];
      }
      rows.push(obj);
    }
    return rows;
  } catch(e) {
    console.error('__loadBukkenMaster_ error:', e && e.message);
    return [];
  }
}

// ══════════════════════════════════════════════════
// [v3.17 H-12] 物件マスタ初期投入セットアップ（GAS エディタから手動実行）
//
//  使い方:
//    1) スプレッドシートで「ファイル → インポート」→ clavis_all_properties_6686.csv をアップロード
//    2) インポートオプション: 「新しいシートを挿入」、シート名「物件マスタ全件」、区切り文字: 自動
//    3) インポート完了後、本関数 setup_verifyBukkenMaster() を実行して件数確認
//    4) 動作確認: setup_testSearchBukken() でクエリ動作テスト
// ══════════════════════════════════════════════════
function setup_verifyBukkenMaster() {
  var ss = SpreadsheetApp.openById(SHEET_ID);
  var sh = ss.getSheetByName(BUKKEN_SHEET_NAME);
  if (!sh) {
    Logger.log('❌ シート「' + BUKKEN_SHEET_NAME + '」が見つかりません。CSV インポートを先に実施してください。');
    return;
  }
  var lastRow = sh.getLastRow();
  var headers = sh.getRange(1, 1, 1, sh.getLastColumn()).getValues()[0];
  Logger.log('✓ シート「' + BUKKEN_SHEET_NAME + '」存在');
  Logger.log('  行数（ヘッダ含む）: ' + lastRow);
  Logger.log('  データ件数: ' + (lastRow - 1));
  Logger.log('  列数: ' + headers.length);
  Logger.log('  ヘッダ: ' + headers.join(', '));
  // 必須列チェック
  var required = ['buken_id', '物件名', '住所', '分類', '住戸数', '竣工年', '共用部1', '専有部1'];
  var missing = required.filter(function(r) { return headers.indexOf(r) < 0; });
  if (missing.length > 0) {
    Logger.log('⚠️ 必須列が不足: ' + missing.join(', '));
  } else {
    Logger.log('✓ 必須列すべて存在');
  }
}

function setup_testSearchBukken() {
  // 認証フリーで内部呼び出しテスト（auth は body 経由のため）
  var result = searchBukken_({ q: '荻窪', limit: 5 });
  Logger.log(JSON.stringify(result, null, 2));
}

// ══════════════════════════════════════════════
//  初回データ投入用（一度だけ実行してください）
//  sanitizeFormula_ 適用で Formula Injection 対策済み
// ══════════════════════════════════════════════
function loadBukkenData() {
  // 2026-05-03 C-M2 hotfix: 既にデータが入っている場合は誤実行で上書きしないようガード
  //   一度実行済み（マスタ投入完了）なので、再実行は ALLOW_LOAD_BUKKEN=YES が必要
  var ss = SpreadsheetApp.openById(SHEET_ID);
  var sheet = ss.getSheetByName('物件マスター') || ss.insertSheet('物件マスター');
  if (sheet.getLastRow() > 1 && getProp('ALLOW_LOAD_BUKKEN') !== 'YES') {
    throw new Error('物件マスターは既にデータが入っています。再投入する場合は ScriptProperties に ALLOW_LOAD_BUKKEN=YES を設定してください。');
  }
  sheet.clearContents();
  var data = [["PASSコード", "物件名", "住所", "住戸数", "メーカー", "システム", "Tebraキー価格", "収納キー価格", "F22TLキー価格", "F22標準キー価格", "出張費", "共用部登録費", "交換費", "事務手数料", "専有部登録費"], ["537847", "ブリリア三鷹禅林寺通り", "東京都三鷹市下連雀３丁目４１", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["471138", "ハーモニーレジデンス池袋メトロゲート", "東京都豊島区池袋本町２丁目８", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["573250", "PREMIUM　CUBE東高円寺DEUX", "東京都杉並区和田３丁目１（以下未定）", "", "シブタニ", "なし", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["288941", "リビオ吉祥寺南町", "東京都武蔵野市吉祥寺南町三丁目１７番（枝番未定）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["185323", "ＰＲＥＭＩＵＭ　ＣＵＢＥ　西荻窪　＃ＭＯ", "東京都杉並区西荻南２－７－２", "", "シブタニ", "なし", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["969947", "バームステージ国分寺", "東京都国分寺市東元町２－７－１７", "", "シブタニ", "なし", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["225828", "シエリア杉並高井戸", "東京都杉並区高井戸西二丁目１１２５番２（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["321320", "パークアクシス池袋イースト", "東京都豊島区東池袋三丁目６６番１２、６６番１３", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["130889", "プレシス蓮田ステーションフロント", "埼玉県蓮田市東５丁目９", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["634557", "ノーブル荻窪", "東京都杉並区宮前二丁目１４－２０", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["066944", "ルネ川口ユトリエ", "埼玉県川口市朝日６－３", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["069261", "オープンレジデンシア荻窪", "東京都杉並区清水２－５", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["060770", "デュオヒルズ青梅ザ・ファースト", "東京都青梅市本町１００１番", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["151863", "プレディア南浦和", "埼玉県さいたま市南区南浦和３丁目２２", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["831100", "ベルジュール東伏見ⅱ", "東京都西東京市富士見町四丁目３番以下未定", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["709216", "エクリューズ", "埼玉県戸田市新曽８０２－２", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["781110", "バウス新狭山", "埼玉県狭山市新狭山２－４－３", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["554603", "ブランズ西荻南三丁目", "東京都杉並区西荻南三丁目１４以下未定", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["170576", "オープンレジデンシア吉祥寺本町テラス", "東京都武蔵野市吉祥寺本町２－２９", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["597463", "プレシス相模原レジデンス", "神奈川県相模原市中央区7-1-20", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["894053", "パークホームズ上板橋", "東京都板橋区上板橋２－２２－１", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["031083", "パークホームズ西荻窪アベニュー", "東京都杉並区上荻4-25-13", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["958109", "ルフォン船堀 ザ・タワーレジデンス", "東京都江戸川区船堀三丁目603番、外(地番)", "", "シブタニ", "Tebra pass A+FACE", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["378110", "カパラもみ", "東京都杉並区荻窪5-20-14", "", "シブタニ", "なし", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["052776", "パークホームズ代々木西原", "東京都渋谷区西原２－２４－１", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["215683", "ガレリアレジデンス大泉学園", "東京都練馬区大泉学園町2-8-1", "", "シブタニ", "Tebra one A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["619984", "パークホームズ城北中央公園", "東京都板橋区桜川２丁目１７－１０", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["671835", "プレイズ大宮日進町", "埼玉県さいたま市北区日進町一丁目40-20（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["279414", "ベルグレードNF", "東京都練馬区貫井3丁目40-23", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["028113", "プレミスト国立ゲートレジデンス", "東京都国立市北２丁目３番３号", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["190972", "パークシティ高田馬場", "東京都新宿区高田馬場四丁目８４４－４", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["183090", "メイツ川越南台", "埼玉県川越市南台３－３－２", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["298279", "コスモ高輪シティフォルム", "東京都港区高輪1-4-23", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["631537", "ルネ花小金井ザ・レジデンス", "東京都小平市花小金井南町一丁目130番11、131番2（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["504430", "プレセダン石神井公園", "東京都練馬区石神井町２－１５－６", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["993111", "プレミスト昭島モリパークレジデンス", "東京都昭島市田中町576-1", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["006754", "アーバンパーク方南町II", "東京都杉並区堀ノ内２－１１－２６", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["372857", "リーフィアレジデンス練馬中村橋", "東京都練馬区中村南3丁目3-1（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["591913", "サンクレイドル東武練馬", "東京都練馬区北町２丁目３２－１", "", "シブタニ", "Tebra one A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["061183", "アーバンパーク高井戸", "東京都杉並区上高井戸２丁目２－４３", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["252251", "クレアシティ根岸", "東京都台東区根岸5丁目1-9", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["467675", "ハーモニーレジデンス新宿 THE NORTH", "東京都新宿区北新宿1丁目23-17", "", "シブタニ", "Tebra one F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["658018", "アクサスレジデンス外苑", "東京都新宿区南元町４番１８号", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["794682", "VilleGrace永福町", "東京都杉並区和泉３－１２－１７", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["075526", "ルネサンスコート本蓮沼", "東京都板橋区清水町７７番７以下未定", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["094940", "ファインスクェア武蔵野テラス", "東京都武蔵野市西久保二丁目443番2、444番1及び3", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["654498", "ザ・レジデンスひばりが丘", "東京都西東京市谷戸町２丁目６−１", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["935469", "ＡＸＡＳ中野中央", "東京都中野区中央3丁目45-17", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["894682", "プラウド京急蒲田", "東京都大田区北糀谷二丁目367番（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["857848", "ファインスクエア武蔵野リアン", "東京都武蔵野市西久保３丁目２４", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["798594", "パークホームズ吉祥寺北　ザ　ガーデン", "東京都練馬区立野町2081番40（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["260760", "プレシス朝霞台ソルティエ", "埼玉県朝霞市宮戸二丁目2006番1（地番）", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["319682", "サンクレイドル日野Ⅱ", "東京都日野市大字日野472番1他", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["368446", "MJR深川住吉", "東京都江東区千石一丁目9番17", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["981998", "サンクレイドル小作", "東京都青梅市新町3丁目3番5", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["106208", "デュオヒルズ福生WEST", "東京都福生市福生６９１", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["040336", "GRANPIA東中野", "東京都中野区東中野１－１４－１０", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["190256", "カサーレ小平", "東京都小平市美園町2丁目19-20", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["764706", "クレヴィア新宿中落合WEST", "東京都新宿区中落合一丁目1127-15（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["276408", "クレヴィア新宿中落合EAST", "東京都新宿区中落合一丁目1127-9（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["344671", "ガリシア中野富士見町", "東京都杉並区和田１丁目２１番", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["445145", "パークタワー東中野グランドエア", "東京都中野区東中野５丁目２番１３号", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["937398", "パークタワー西新宿", "東京都新宿区西新宿５丁目817番地（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["290700", "バウス金町", "東京都葛飾区金町一丁目15番1（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["008781", "プレミスト新小岩ルネ", "東京都江戸川区中央1丁目1539番の1", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["136789", "ゼルカヴァ杉並", "東京都杉並区宮前５－２５－１９", "", "シブタニ", "Tebra one A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["831312", "グランフォーレ立川", "東京都立川市錦町２－３－４", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["984174", "Brillia四谷三丁目", "東京都新宿区舟町３－１", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["290743", "ローレルコート中杉通り", "東京都中野区白鷺2丁目6-25", "", "シブタニ", "LEAD", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["084018", "プラネスーペリア三鷹下連雀", "東京都三鷹市下連雀2丁目21-17", "", "シブタニ", "LEAD", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["007858", "ポレスターステーションシティ久喜", "埼玉県久喜市久喜中央2丁目9-30", "", "シブタニ", "LEAD", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["022055", "プレシス田無", "東京都西東京市田無町1-6-15", "", "シブタニ", "F-ics", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["517977", "ビバリーホームズ上井草", "東京都練馬区下石神井5丁目18-6", "", "シブタニ", "なし", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["499291", "ディアスタ武蔵野　翠の邸", "東京都武蔵野市西久保1丁目12-4", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["779671", "クレイシア品川東大井", "東京都品川区東大井３－１６－９", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["429285", "コンシェリア目白ＴＨＥ ＧＲＡＮＤ ＲＥＳＩＤＥＮＣＥ", "東京都新宿区下落合2丁目10-10", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["650877", "シルフィ鷺宮", "東京都中野区鷺宮3-41-13", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["971161", "ガリシア新宿御苑", "東京都新宿区新宿1-26", "", "シブタニ", "Tebra one A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["617974", "プレシス武蔵境", "東京都武蔵野市境南町一丁目32-6", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["446935", "プレセダンヒルズ阿佐ヶ谷", "東京都杉並区阿佐谷北2丁目13-14", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["841220", "リストレジデンス王子", "東京都北区豊島１丁目4-8", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["893652", "アゼスト下落合", "東京都新宿区上落合1丁目9-10", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["993448", "グローベル ザ・高円寺プレミアム", "東京都杉並区高円寺南4丁目5-7", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["511129", "ローレルコート杉並松庵", "東京都杉並区松庵2-18-20", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["832316", "東新宿レジデンシャルタワー", "東京都新宿区歌舞伎町2丁目4-14", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["858567", "ザ・グローベル南大塚", "東京都豊島区南大塚3丁目42-1", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["031841", "レ・ジェイド桜上水ティアラ", "東京都世田谷区桜上水４丁目２０−６", "", "シブタニ", "F-ics", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["578121", "西荻窪スカイハイツ", "東京都杉並区西荻北３丁目１２−１３", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["092381", "アニモ新丸子", "神奈川県川崎市中原区新丸子東1丁目821-1", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["408422", "ビバリーホームズ石神井台", "東京都練馬区石神井台7-18-26", "", "シブタニ", "なし", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["653238", "リビオ荻窪レジデンス", "東京都杉並区南荻窪１丁目７−１８", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["852024", "レガリス高円寺", "東京都中野区大和町1丁目1-25", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["860895", "コルティーラ浜田山", "東京都杉並 浜田山4-30-10", "", "シブタニ", "なし", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["180065", "ルピアコート宮前平", "神奈川県川崎市宮前区宮前平２丁目５−２３", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["780261", "ブリリア東中野ＳｔａｔｉｏｎＦｒｏｎｔ", "東京都東京都中野区東中野2-24-13", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["435932", "シティインデックス中野", "東京都中野区新井一丁目40-2", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["192800", "プレシス中野哲学堂パークフロント", "東京都中野区松が丘2丁目31-12（住居表示）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["347822", "ローレルコート石神井公園", "東京都練馬区高野台５丁目２９－３", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["501791", "デュオヒルズ西大宮ザ・グランテラス", "埼玉県さいたま市西区西大宮３丁目３８−１", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["126329", "アールブラン武蔵境", "東京都武蔵野市境南町2-27-3", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["589617", "ピアース西荻窪", "東京都杉並区西荻南3-7-13", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["224326", "レジデンシャル東中野", "東京都中野区東中野1-54", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["588248", "レガリス高円寺Ⅱ", "東京都中野区野方1-40", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["123028", "ベルジュール武蔵野桜堤", "東京都武蔵野市桜堤2丁目12-15", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["441478", "ハーモニーレジデンス中野富士見町", "東京都杉並区和田2丁目16番20号", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["352001", "クレヴィスタ練馬武蔵関", "東京都練馬区関町東2-6", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["522157", "ブレッサ西日暮里", "東京都北区田端1-11-7", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["640606", "ベルジュール三鷹ステーションハウス", "東京都三鷹市上連雀1丁目2番", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["722613", "デュフレ阿佐ヶ谷", "東京都杉並区阿佐谷南一丁目5番1号（住居表示）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["666917", "ＫＤＸレジデンス池袋ウエスト", "東京都板橋区中丸町2番6", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["538081", "広尾ヴィラスクエア", "東京都渋谷区東4丁目7-4", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["949271", "EsTRUTH RYOGOKUⅡ", "東京都墨田区石原1-41-4", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["763003", "神楽坂ザ・レジデンス", "東京都新宿区神楽坂白銀町2-12", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["722208", "HY’s Salire 用賀", "東京都世田谷区玉川台２－３９－８", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["641882", "バームステージ大島", "東京都江東区大島８丁目２１−１３", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["694591", "ARISACOURT", "東京都豊島区池袋２－２１－１", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["157501", "ベルジュール国立ウエスト", "東京都国立市中３丁目１１−３３", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["746777", "AIFLAT SAKURAJOSUI(AIFLAT桜上水)", "東京都杉並区下高井戸1丁目31番2号（住居表示）", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["343282", "ルジェンテ品川南大井フレクシス", "東京都品川区南大井２丁目１−１１", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["642924", "クレアシティ所沢", "東京都", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["503316", "デュフレ渋谷本町", "東京都渋谷区本町６丁目８−６", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["084778", "ベルシード氷川台", "東京都練馬区氷川台3-1-17", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["971480", "ステイツ武蔵新城エスタシオン", "神奈川県川崎市中原区上新城2丁目7-11", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["161442", "パティーナ桜台Duo", "東京都練馬区豊玉上2-3-27", "", "シブタニ", "Tebra one A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["368052", "ブリシア荻窪一丁目", "東京都杉並区荻窪一丁目27-5", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["429703", "グラサージュ武蔵境アヴニール", "東京都三鷹市井口3-1", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["884788", "パークホームズ市ヶ谷ヒルトップレジデンス", "東京都新宿区納戸町３８番３（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["833893", "プレシス武蔵境プロスタイル", "東京都武蔵野市境南町2丁目27-3", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["411791", "クレヴィスタ武蔵中原", "神奈川県川崎市中原区上小田中3丁目7-3", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["512694", "MAXIV西荻窪AZ", "東京都杉並区西荻北１丁目2番19", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["500721", "Brilia三鷹下連雀", "東京都三鷹市下連雀4丁目315番16、17(地番)", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["568056", "バウス新中野", "東京都中野区本町5丁目37－11", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["771376", "パークホームズ杉並上荻", "東京都杉並区上荻3-27", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["009173", "ルフォンプログレ中野坂上", "東京都中野区本町１－１３", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["411327", "オープンレジデンシア吉祥寺本町プレイス", "東京都武蔵野市吉祥寺本町３－１０－１０", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["822820", "プレディア東中野", "東京都中野区東中野５－１７－２８", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["473609", "リライア武蔵小杉", "神奈川県川崎市中原区上丸子山王町1丁目1404", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["049146", "ローレルコート笹塚", "東京都杉並区方南1丁目46番", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["241014", "AXAS池袋レジデンス", "東京都豊島区池袋1丁目16-26", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["906345", "ウエリス井の頭公園", "東京都三鷹市下連雀１", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["924606", "シーフォルム外苑前", "東京都港区北青山２ー１２", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["278501", "サンクレイドル学芸大学", "東京都世田谷区野沢3丁目5-19", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["626336", "ピアース中野坂上", "東京都中野区中央１-30-29", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["627137", "プラウド綱島ＳＳＴ", "神奈川県横浜市港北区綱島東四丁目", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["024537", "ウエリス新宿早稲田の森", "東京都新宿区 大久保3-1-3", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["071505", "サンクレイドル西東京", "東京都西東京市芝久保町2丁目13-19", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["289211", "ディアスタ宮崎台", "神奈川県川崎市宮前区宮崎３丁目１０番９他", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["252892", "ルイシャトレ川口青木リバーパーク", "埼玉県川口市青木2丁目13−23", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["027964", "Brillia Tower 代々木公園 CLASSY", "東京都渋谷区富ヶ谷1-49", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["435867", "モディア市ヶ谷", "東京都新宿区払方町２?４", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["748286", "アトラス荻窪大田黒公園", "東京都東京都杉並区荻窪３丁目４７－１６", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["105941", "パークナード代官山", "東京都渋谷区恵比寿西２丁目２０－２（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["331587", "パークルール恵比寿", "東京都渋谷区恵比寿2-5-4", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["099886", "グランドメゾン目黒プレイス", "東京都目黒区下目黒２丁目21-18", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["346919", "アトラス東高円寺", "東京都杉並区和田3-54-11", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["027888", "ブランズ中野富士見町パークナード", "東京都中野区本町五丁目39-10他（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["380473", "グローベル　ザ・中浦和　日向ノ杜", "埼玉県さいたま市桜区西堀８-402-1（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["271838", "ＡＲＫＭＡＲＫ中野坂上", "東京都中野区東中野１丁目１７番３号", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["670097", "プレシス大宮ヴェルデ", "埼玉県さいたま市大宮区大成町二丁目206", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["622760", "アーバネックス銀座東Ⅱ", "東京都中央区湊1丁目12-3", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["502927", "ドゥーエ武蔵浦和", "埼玉県さいたま市南区白幡五丁目3番23号", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["406614", "グランツオーベル中野", "東京都中野区5-26-3", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["796240", "ドゥーエ早稲田", "東京都新宿区西早稲田2-6-1", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["952029", "ディアナガーデン鷹番", "東京都目黒区鷹番3-21-9", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["098446", "RELUXIA北新宿", "東京都新宿区北新宿3-39-8", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["942517", "パークホームズ浦和常盤十丁目", "埼玉県さいたま市浦和区常盤10-16-16", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["837206", "PREMIUM CUBE中野", "東京都中野区中野2-16-4", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["070691", "アトラス練馬レジデンス", "東京都練馬区豊玉北6丁目4番7（地番）", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["555615", "エスジーコート元浅草", "東京都台東区元浅草4丁目4-9", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["151061", "サンクレイドル立川幸町", "東京都立川幸町1丁目31-23", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["047546", "ベルシード板橋NORTH", "東京都板橋区蓮根3丁目", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["723508", "プライムメゾン方南町", "東京都中野区弥生町6-10-12", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["050670", "ローレルコート新宿夏目坂", "東京都新宿区戸山１丁目１５?１３", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["165317", "クレヴィア西荻窪", "東京都杉並区西麻布荻南二丁目18", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["236821", "オープンレジデンシア中野坂上コート", "東京都中野区本町3丁目15番1", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["628315", "フィカーサプレミア", "東京都練馬区西大泉5丁目33-7", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["375866", "アビティグランデ砧", "東京都世田谷砧7-18", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["710941", "オープンレジデンシア西荻窪", "東京都杉並区西荻北三丁目9番1号", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["743137", "Ｌａ　Ｄｏｕｃｅｕｒ四ツ木Ｅａｓｔ", "東京都葛飾区四つ木３丁目１−30", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["850590", "Ｌａ　Ｄｏｕｃｅｕｒ四ツ木Ｗｅｓｔ", "東京都葛飾区四つ木3-1-31", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["222619", "PREMIUM　CUBE新宿中井", "東京都新宿区中井2-13-1", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["341920", "クレヴィスタ高円寺", "東京都杉並区高円寺4-43-6", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["343832", "ヴァースクレイシア中野富士見町", "東京都中野区弥生町5-1", "", "シブタニ", "なし", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["448712", "コンシェリア大森ザ・レジデンス", "東京都大田区中央２丁目５－１６", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["109732", "リビオ東中野ヒルトップ", "東京都中野区東中野１－３２－１", "", "シブタニ", "Tebra pass F", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["140698", "リーフィアレジデンス杉並　井草森公園", "東京都杉並区井草四丁目18-16", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["937824", "レピュア武蔵関", "東京都練馬区関町東２丁目５?８", "", "シブタニ", "なし", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["292362", "PREMIUM CUBE 東高円寺", "東京都杉並区高円寺南1-31-8", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["222311", "ルネサンスコート高田馬場", "東京都新宿区高田馬場3-32", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["188361", "オープンレジデンシア吉祥寺本町", "東京都武蔵野市吉祥寺本町2-28-16", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["794520", "オープンレジデンシア大井町フロントコート", "東京都品川区東大井5丁目444番2他(地番)", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["963590", "パークホームズ練馬富士見台ステーションゲート", "東京都練馬区貫井3丁目473-21", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["904473", "Brillia City ふじみ野", "埼玉県ふじみ野市大原2丁目1735番1他(地番)", "", "シブタニ", "Tebra pass A", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500], ["544782", "クレイシアIDZ芦花公園", "東京都杉並区上高井戸１丁目２２－４", "", "シブタニ", "なし", 15400, 6600, 7100, 3900, 8000, 5000, 5000, 2500, 2500]];

  // P1-2 是正 相当: Formula Injection 対策 - 各セルに sanitizeFormula_ を適用
  var sanitized = data.map(function(row, rowIdx) {
    // ヘッダ行はそのまま（通常 sanitize 不要だが念のため先頭記号チェック）
    return row.map(function(cell) {
      // 数値はそのまま、文字列のみ sanitize
      if (typeof cell === 'number') return cell;
      return sanitizeFormula_(cell);
    });
  });

  sheet.getRange(1, 1, sanitized.length, sanitized[0].length).setValues(sanitized);
  SpreadsheetApp.flush();
  Logger.log('完了: ' + (sanitized.length - 1) + '件（Formula Injection 対策適用済み）');
}

// ══════════════════════════════════════════════
//  セットアップ用（初回のみ手動実行）
// ══════════════════════════════════════════════
//   1) setupVerifyAuditLogTrigger() — 監査ログ日次検証トリガー登録
//   2) setup_generateHmacKey() — WORKER_HMAC_KEY 生成（※Worker と同値を手動で両側に設定）
//   3) setup_generateLogKey()  — WORKER_LOG_KEY 生成
function setup_generateHmacKey() {
  var bytes = Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
  var key = sha256_gas(bytes);
  Logger.log('WORKER_HMAC_KEY (copy to Cloudflare & GAS): ' + key);
  return key;
}
function setup_generateLogKey() {
  var bytes = Utilities.getUuid().replace(/-/g, '') + Utilities.getUuid().replace(/-/g, '');
  var key = sha256_gas(bytes);
  Logger.log('WORKER_LOG_KEY (copy to Cloudflare & GAS): ' + key);
  return key;
}
