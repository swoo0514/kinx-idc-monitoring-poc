// Zabbix 7.0 웹훅 미디어타입 스크립트 — 이벤트를 알림 게이트웨이로 전달
// 배선 절차·파라미터 표·근거는 bot/GATEWAY_GUIDE.md 참조
var params = JSON.parse(value);

var payload = {
    source: params.source,
    event_id: params.event_id,
    trigger_id: params.trigger_id,
    event_value: parseInt(params.event_value) || 1,
    event_name: params.event_name,
    nseverity: parseInt(params.nseverity),
    host: params.host,
    tags: params.tags_json ? JSON.parse(params.tags_json) : []
};

var req = new HttpRequest();
req.addHeader('Content-Type: application/json');
req.addHeader('X-Gateway-Token: ' + params.token);
var resp = req.post(params.gateway_url + '/webhook/zabbix', JSON.stringify(payload));

if (req.getStatus() !== 200) {
    throw 'gateway returned ' + req.getStatus() + ': ' + resp;
}
return 'OK';
