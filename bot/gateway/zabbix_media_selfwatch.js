// Zabbix 7.0 웹훅 미디어타입 — 감시 도구 자신의 고장을 Slack 으로 직접 보낸다.
//
// 왜 따로 두나 — 게이트웨이가 죽었다는 알림을 게이트웨이로 보내면 그 알림도 같이 죽는다.
// 이 경로는 Zabbix 서버 안에서 Slack 으로 바로 나가므로 게이트웨이와 무관하게 동작한다.
// 채널도 분리한다. 봇 채널은 봇이 죽으면 조용해지는데, 그 조용함이 곧 증상이라
// 같은 곳에 경고를 넣으면 조용함과 경고가 한 화면에서 섞인다.
//
// 배선 절차는 ansible/gateway_heartbeat.yml, 근거는 bot/GATEWAY_GUIDE.md §20.
var params = JSON.parse(value);

var icon = params.event_value === '0' ? ':large_green_circle:' : ':rotating_light:';
var head = params.event_value === '0' ? '해소' : '발생';

var text = icon + ' *감시 도구 자체 알림 — ' + head + '*\n'
    + '*' + params.event_name + '*\n'
    + '호스트: `' + params.host + '`  ·  심각도: ' + params.severity + '\n'
    + params.event_date + ' ' + params.event_time;

// {EVENT.OPDATA} 는 넣지 않는다. 트리거의 운영 데이터 칸이 비어 있으면 Zabbix 가
// 조건식 아이템의 마지막 값을 대신 넣는데, 이 트리거에서는 그 값이 늘 1 이라
// 뜻 없는 숫자 한 줄이 붙는다(랩 실측).

var req = new HttpRequest();
req.addHeader('Content-Type: application/json; charset=utf-8');
req.addHeader('Authorization: Bearer ' + params.bot_token);
var resp = req.post('https://slack.com/api/chat.postMessage',
    JSON.stringify({ channel: params.channel, text: text }));

if (req.getStatus() !== 200) {
    throw 'slack http ' + req.getStatus() + ': ' + resp;
}
// Slack 은 실패해도 200 을 준다. ok 를 보지 않으면 안 간 것을 못 알아챈다.
var body = JSON.parse(resp);
if (!body.ok) {
    throw 'slack error: ' + body.error;
}
return 'OK';
