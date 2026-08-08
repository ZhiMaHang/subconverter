#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <rapidjson/document.h>
#include <yaml-cpp/yaml.h>

#include "generator/config/subexport.h"
#include "parser/subparser.h"
#include "utils/base64/base64.h"
#include "utils/string.h"

namespace
{
constexpr const char *TEST_UUID = "11111111-1111-4111-8111-111111111111";

void require(bool condition, const std::string &message)
{
    if(!condition)
        throw std::runtime_error(message);
}

Proxy parseLink(const std::string &link)
{
    Proxy node;
    explode(link, node);
    return node;
}

YAML::Node exportClash(Proxy node)
{
    std::vector<Proxy> nodes{std::move(node)};
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    ext.clash_new_field_name = true;
    YAML::Node output;
    proxyToClash(nodes, output, groups, false, ext);
    return output;
}

std::string exportSingBox(Proxy node)
{
    std::vector<Proxy> nodes{std::move(node)};
    std::vector<RulesetContent> rules;
    ProxyGroupConfigs groups;
    extra_settings ext;
    ext.nodelist = true;
    return proxyToSingBox(nodes, "{}", rules, groups, ext);
}

void testRealityIPv6()
{
    const std::string link =
        std::string("vless://") + TEST_UUID +
        "@[2001:db8::10]:443?encryption=none&security=reality&type=tcp"
        "&sni=cdn.example.com&fp=chrome&flow=xtls-rprx-vision"
        "&pbk=FAKE_PUBLIC_KEY&sid=&spx=%2Fprobe"
        "&alpn=h2%2Chttp%2F1.1&packetEncoding=xudp#Reality%20IPv6";

    Proxy node = parseLink(link);
    require(node.Type == ProxyType::VLESS, "Reality URI was not recognized as VLESS");
    require(node.Hostname == "2001:db8::10", "IPv6 authority was not normalized");
    require(node.Port == 443, "VLESS port was not parsed");
    require(node.Security == "reality" && node.TLSSecure, "Reality security was not retained");
    require(node.ServerName == "cdn.example.com", "Reality SNI was not retained");
    require(node.ClientFingerprint == "chrome", "Client fingerprint was not retained");
    require(node.RealityPublicKey == "FAKE_PUBLIC_KEY", "Reality public key was not retained");
    require(node.RealityShortId.empty(), "Empty Reality short ID must remain valid");
    require(node.RealitySpiderX == "/probe", "Reality spiderX was not decoded");
    require(node.Alpn.size() == 2 && node.Alpn[1] == "http/1.1", "ALPN list was not decoded");

    YAML::Node clash = exportClash(node);
    const YAML::Node proxy = clash["proxies"][0];
    require(proxy["type"].as<std::string>() == "vless", "Clash VLESS type missing");
    require(proxy["server"].as<std::string>() == "2001:db8::10", "Clash IPv6 server is invalid");
    require(proxy["tls"].as<bool>(), "Clash Reality node must enable TLS");
    require(proxy["client-fingerprint"].as<std::string>() == "chrome", "Clash client fingerprint is wrong");
    require(proxy["reality-opts"]["public-key"].as<std::string>() == "FAKE_PUBLIC_KEY", "Clash Reality key missing");
    require(proxy["reality-opts"]["short-id"].as<std::string>().empty(), "Clash empty Reality short ID was dropped");

    std::vector<Proxy> nodes{node};
    extra_settings raw_ext;
    raw_ext.nodelist = true;
    const std::string raw = proxyToSingle(nodes, 16, raw_ext);
    require(raw.find("vless://" + std::string(TEST_UUID) + "@[2001:db8::10]:443?") == 0, "Raw VLESS IPv6 authority is invalid");
    require(raw.find("security=reality") != std::string::npos, "Raw VLESS Reality security missing");
    require(raw.find("security=xtls") == std::string::npos, "Raw VLESS emitted obsolete security=xtls");
    require(raw.find("sid=") != std::string::npos, "Raw VLESS empty Reality short ID missing");
    require(raw.find("spx=%2Fprobe") != std::string::npos, "Raw VLESS spiderX was not encoded");

    const std::string singbox_text = exportSingBox(node);
    rapidjson::Document singbox;
    singbox.Parse(singbox_text.c_str());
    require(!singbox.HasParseError(), "sing-box output is not valid JSON");
    const auto &outbound = singbox["outbounds"][0];
    require(std::string(outbound["type"].GetString()) == "vless", "sing-box VLESS type missing");
    require(std::string(outbound["tls"]["server_name"].GetString()) == "cdn.example.com", "sing-box SNI is wrong");
    require(std::string(outbound["tls"]["utls"]["fingerprint"].GetString()) == "chrome", "sing-box uTLS fingerprint is wrong");
    require(std::string(outbound["tls"]["reality"]["public_key"].GetString()) == "FAKE_PUBLIC_KEY", "sing-box Reality key missing");
}

void testWebSocketTLS()
{
    const std::string link =
        std::string("vless://") + TEST_UUID +
        "@ws.example.com:443?security=tls&type=ws&host=edge.example.com"
        "&path=%2Fws%3Fed%3D1&ed=2048&eh=Sec-WebSocket-Protocol"
        "&allowInsecure=1#WS%20TLS";
    Proxy node = parseLink(link);
    require(node.Type == ProxyType::VLESS, "WS VLESS URI was not parsed");
    require(node.TransferProtocol == "ws", "WS transport was not retained");
    require(node.Host == "edge.example.com" && node.Path == "/ws?ed=1", "WS host/path was not decoded");
    require(node.MaxEarlyData == 2048, "WS early data length missing");
    require(node.EarlyDataHeaderName == "Sec-WebSocket-Protocol", "WS early data header missing");
    require(node.AllowInsecure.get(), "Legacy allowInsecure was not accepted");
    require(node.ClientFingerprint == "chrome", "Default VLESS TLS client fingerprint is wrong");

    YAML::Node clash = exportClash(node);
    const YAML::Node proxy = clash["proxies"][0];
    require(proxy["network"].as<std::string>() == "ws", "Clash WS network missing");
    require(proxy["ws-opts"]["path"].as<std::string>() == "/ws?ed=1", "Clash WS path is wrong");
    require(proxy["ws-opts"]["max-early-data"].as<uint32_t>() == 2048, "Clash WS early data missing");
    require(proxy["skip-cert-verify"].as<bool>(), "Clash legacy allowInsecure mapping is wrong");

    std::vector<Proxy> raw_nodes{node};
    extra_settings raw_ext;
    raw_ext.nodelist = true;
    const std::string raw = proxyToSingle(raw_nodes, 16, raw_ext);
    require(raw.find("allowInsecure=1") != std::string::npos, "Raw VLESS dropped legacy allowInsecure");
    const Proxy round_trip = parseLink(trim(raw));
    require(round_trip.Type == ProxyType::VLESS && round_trip.AllowInsecure.get(), "Legacy allowInsecure did not survive raw round-trip");

    const std::string singbox_text = exportSingBox(node);
    rapidjson::Document singbox;
    singbox.Parse(singbox_text.c_str());
    const auto &transport = singbox["outbounds"][0]["transport"];
    require(transport["max_early_data"].GetUint() == 2048, "sing-box WS early data missing");
    require(std::string(transport["early_data_header_name"].GetString()) == "Sec-WebSocket-Protocol", "sing-box WS early data header missing");
}

void testCanonicalHttpAndClashInput()
{
    const std::string link =
        std::string("vless://") + TEST_UUID +
        "@h2.example.com:443?security=tls&type=http&host=origin.example.com&path=%2Fh2#HTTP";
    Proxy node = parseLink(link);
    require(node.TransferProtocol == "h2", "Canonical type=http was not normalized to H2");

    YAML::Node clash = exportClash(node);
    require(clash["proxies"][0]["network"].as<std::string>() == "h2", "Canonical HTTP did not export as Mihomo H2");
    require(clash["proxies"][0]["h2-opts"]["host"][0].as<std::string>() == "origin.example.com", "Mihomo H2 host is wrong");

    std::vector<Proxy> raw_nodes{node};
    extra_settings raw_ext;
    raw_ext.nodelist = true;
    const std::string raw = proxyToSingle(raw_nodes, 16, raw_ext);
    require(raw.find("type=http") != std::string::npos, "H2 did not export as canonical type=http");
    require(raw.find("type=h2") == std::string::npos, "Non-canonical type=h2 was emitted");

    const std::string singbox_text = exportSingBox(node);
    rapidjson::Document singbox;
    singbox.Parse(singbox_text.c_str());
    const auto &transport = singbox["outbounds"][0]["transport"];
    require(std::string(transport["type"].GetString()) == "http", "sing-box H2 transport mapping is wrong");
    require(std::string(transport["host"][0].GetString()) == "origin.example.com", "sing-box HTTP host is wrong");

    const std::string clash_input = R"(proxies:
  - name: Clash Reality
    type: vless
    server: clash.example.com
    port: 443
    uuid: 22222222-2222-4222-8222-222222222222
    encryption: none
    flow: xtls-rprx-vision
    tls: true
    servername: sni.example.com
    client-fingerprint: firefox
    network: grpc
    grpc-opts:
      grpc-service-name: demo
    reality-opts:
      public-key: CLASH_FAKE_KEY
      short-id: ""
)";
    std::vector<Proxy> parsed;
    explodeSub(clash_input, parsed);
    require(parsed.size() == 1 && parsed[0].Type == ProxyType::VLESS, "Clash VLESS input was not parsed");
    require(parsed[0].Security == "reality" && parsed[0].TransferProtocol == "grpc", "Clash VLESS security/transport is wrong");
    require(parsed[0].Path == "demo" && parsed[0].ClientFingerprint == "firefox", "Clash VLESS options were lost");
}

void testSubscriptionAndValidation()
{
    const Proxy defaults = parseLink(std::string("vless://") + TEST_UUID + "@default.example.com:80#Default");
    require(defaults.Type == ProxyType::VLESS && defaults.Security == "none" && defaults.TransferProtocol == "tcp", "VLESS defaults were not applied");

    const std::string uri = std::string("vless://") + TEST_UUID + "@sub.example.com:8443?security=none#Sub";
    std::vector<Proxy> nodes;
    explodeSub(base64Encode(uri + "\n"), nodes);
    require(nodes.size() == 1 && nodes[0].TransferProtocol == "tcp", "Base64 VLESS subscription was not parsed");

    require(parseLink("vless://@example.com:443?security=tls#bad").Type == ProxyType::Unknown, "Empty VLESS UUID was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:0#bad").Type == ProxyType::Unknown, "Port zero was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:70000#bad").Type == ProxyType::Unknown, "Out-of-range port was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:443abc#bad").Type == ProxyType::Unknown, "Non-numeric port was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@2001:db8::1:443#bad").Type == ProxyType::Unknown, "Unbracketed IPv6 was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:443?type=kcp&seed=lost#bad").Type == ProxyType::Unknown, "Unsupported KCP transport was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:443?security=reality&type=tcp#bad").Type == ProxyType::Unknown, "Reality without public key was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:443?security=tls&type=tcp&ech=config#bad").Type == ProxyType::Unknown, "Unsupported URI security option was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:443?security=tls&type=tcp&ech=#bad").Type == ProxyType::Unknown, "Empty unsupported URI security option was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:443?security=unknown&type=tcp#bad").Type == ProxyType::Unknown, "Unknown VLESS security mode was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:443?security=tls&security=none&type=tcp#bad").Type == ProxyType::Unknown, "Duplicate VLESS query key was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:443?type=tcp&headerType=http&method=POST#bad").Type == ProxyType::Unknown, "Unsupported VLESS TCP HTTP method was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:443?type=grpc&ed=2048#bad").Type == ProxyType::Unknown, "Early data on unsupported transport was accepted");
    require(parseLink(std::string("vless://") + TEST_UUID + "@example.com:443?type=ws&ed=invalid#bad").Type == ProxyType::Unknown, "Invalid VLESS early-data size was accepted");
}

void testUnsupportedClashOptionsAreRejected()
{
    const std::string clash_input = R"(proxies:
  - name: WS custom header
    type: vless
    server: ws.example.com
    port: 443
    uuid: 33333333-3333-4333-8333-333333333333
    tls: true
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: edge.example.com
        X-Custom: must-not-disappear
  - name: HTTP POST
    type: vless
    server: http.example.com
    port: 443
    uuid: 44444444-4444-4444-8444-444444444444
    tls: true
    network: http
    http-opts:
      method: POST
      path: [/submit]
  - name: Rich XHTTP
    type: vless
    server: xhttp.example.com
    port: 443
    uuid: 55555555-5555-4555-8555-555555555555
    tls: true
    network: xhttp
    xhttp-opts:
      path: /x
      mode: stream-one
      headers:
        X-Custom: must-not-disappear
  - name: Certificate pin
    type: vless
    server: pin.example.com
    port: 443
    uuid: 66666666-6666-4666-8666-666666666666
    tls: true
    fingerprint: PINNED_CERTIFICATE_HASH
  - name: Missing Reality key
    type: vless
    server: reality.example.com
    port: 443
    uuid: 77777777-7777-4777-8777-777777777777
    tls: true
    reality-opts:
      short-id: ""
  - name: Client certificate
    type: vless
    server: mtls.example.com
    port: 443
    uuid: 88888888-8888-4888-8888-888888888888
    tls: true
    certificate: CLIENT_CERTIFICATE
    private-key: CLIENT_PRIVATE_KEY
  - name: ECH
    type: vless
    server: ech.example.com
    port: 443
    uuid: 99999999-9999-4999-8999-999999999999
    tls: true
    ech-opts:
      enable: true
      config: ECH_CONFIG
  - name: Reality hybrid KEM
    type: vless
    server: hybrid.example.com
    port: 443
    uuid: aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
    tls: true
    reality-opts:
      public-key: REALITY_KEY
      short-id: ""
      support-x25519mlkem768: true
)";
    std::vector<Proxy> parsed;
    explodeSub(clash_input, parsed);
    require(parsed.empty(), "Clash VLESS options that cannot round-trip were silently simplified");
}

void testAdditionalTargetsAndUnsupportedTransport()
{
    Proxy reality = parseLink(
        std::string("vless://") + TEST_UUID +
        "@target.example.com:443?security=reality&type=tcp&sni=sni.example.com"
        "&flow=xtls-rprx-vision&pbk=TARGET_FAKE_KEY&sid=1234#Target");
    std::vector<Proxy> nodes{reality};
    std::vector<RulesetContent> rules;
    ProxyGroupConfigs groups;

    extra_settings quanx_ext;
    quanx_ext.nodelist = true;
    const std::string quanx = proxyToQuanX(nodes, "", rules, groups, quanx_ext);
    require(quanx.find("vless = target.example.com:443") != std::string::npos, "Quantumult X VLESS output missing");
    require(quanx.find("reality-base64-pubkey=TARGET_FAKE_KEY") != std::string::npos, "Quantumult X Reality key missing");

    nodes = {reality};
    extra_settings loon_ext;
    loon_ext.nodelist = true;
    const std::string loon = proxyToLoon(nodes, "", rules, groups, loon_ext);
    require(loon.find("VLESS,target.example.com,443") != std::string::npos, "Loon VLESS output missing");
    require(loon.find("public-key=\"TARGET_FAKE_KEY\"") != std::string::npos, "Loon Reality key missing");

    Proxy xhttp = parseLink(
        std::string("vless://") + TEST_UUID +
        "@xhttp.example.com:443?security=tls&type=xhttp&host=origin.example.com&path=%2Fx&mode=stream-one#XHTTP");
    YAML::Node clash = exportClash(xhttp);
    require(clash["proxies"][0]["network"].as<std::string>() == "xhttp", "Mihomo XHTTP output missing");
    require(clash["proxies"][0]["xhttp-opts"]["mode"].as<std::string>() == "stream-one", "Mihomo XHTTP mode missing");

    const std::string singbox_text = exportSingBox(xhttp);
    rapidjson::Document singbox;
    singbox.Parse(singbox_text.c_str());
    require(singbox["outbounds"].IsArray() && singbox["outbounds"].Empty(), "Unsupported sing-box XHTTP was silently downgraded");

    Proxy http_upgrade = parseLink(
        std::string("vless://") + TEST_UUID +
        "@upgrade.example.com:443?security=tls&type=httpupgrade&host=origin.example.com&path=%2Fupgrade#HTTPUpgrade");
    require(http_upgrade.Type == ProxyType::VLESS && http_upgrade.TransferProtocol == "httpupgrade", "VLESS HTTPUpgrade URI was not parsed");
    clash = exportClash(http_upgrade);
    require(clash["proxies"][0]["network"].as<std::string>() == "ws", "Mihomo HTTPUpgrade compatibility network is wrong");
    require(clash["proxies"][0]["ws-opts"]["v2ray-http-upgrade"].as<bool>(), "Mihomo HTTPUpgrade flag missing");

    std::vector<Proxy> parsed_upgrade;
    explodeSub(YAML::Dump(clash), parsed_upgrade);
    require(parsed_upgrade.size() == 1 && parsed_upgrade[0].TransferProtocol == "httpupgrade", "Mihomo HTTPUpgrade did not round-trip");

    const std::string upgrade_singbox_text = exportSingBox(http_upgrade);
    rapidjson::Document upgrade_singbox;
    upgrade_singbox.Parse(upgrade_singbox_text.c_str());
    require(std::string(upgrade_singbox["outbounds"][0]["transport"]["type"].GetString()) == "httpupgrade", "sing-box HTTPUpgrade transport is wrong");

    Proxy http_upgrade_early = parseLink(
        std::string("vless://") + TEST_UUID +
        "@upgrade.example.com:443?security=tls&type=httpupgrade&host=origin.example.com&path=%2Fupgrade"
        "&ed=2048&eh=Sec-WebSocket-Protocol#HTTPUpgrade%20Early");
    require(http_upgrade_early.Type == ProxyType::VLESS && http_upgrade_early.MaxEarlyData == 2048, "HTTPUpgrade early data was not parsed");
    clash = exportClash(http_upgrade_early);
    require(clash["proxies"][0]["ws-opts"]["v2ray-http-upgrade-fast-open"].as<bool>(), "Mihomo HTTPUpgrade fast-open flag missing");
    require(clash["proxies"][0]["ws-opts"]["early-data-header-name"].as<std::string>() == "Sec-WebSocket-Protocol", "Mihomo HTTPUpgrade early-data header missing");

    std::vector<Proxy> raw_upgrade_nodes{http_upgrade_early};
    extra_settings raw_upgrade_ext;
    raw_upgrade_ext.nodelist = true;
    const std::string raw_upgrade = proxyToSingle(raw_upgrade_nodes, 16, raw_upgrade_ext);
    require(raw_upgrade.find("ed=2048") != std::string::npos && raw_upgrade.find("eh=Sec-WebSocket-Protocol") != std::string::npos,
            "Raw HTTPUpgrade early-data options were lost");

    const std::string unsupported_upgrade_singbox_text = exportSingBox(http_upgrade_early);
    rapidjson::Document unsupported_upgrade_singbox;
    unsupported_upgrade_singbox.Parse(unsupported_upgrade_singbox_text.c_str());
    require(unsupported_upgrade_singbox["outbounds"].Empty(), "sing-box HTTPUpgrade early data was silently dropped");
}
}

int main()
{
    try
    {
        testRealityIPv6();
        testWebSocketTLS();
        testCanonicalHttpAndClashInput();
        testSubscriptionAndValidation();
        testUnsupportedClashOptionsAreRejected();
        testAdditionalTargetsAndUnsupportedTransport();
        std::cout << "VLESS tests passed" << std::endl;
        return 0;
    }
    catch(const std::exception &error)
    {
        std::cerr << "VLESS test failure: " << error.what() << std::endl;
        return 1;
    }
}
