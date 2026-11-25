/**
 * Clash Verge Rev / Mihomo Party 全局扩展脚本（JavaScript）
 * 作用：
 *   1. 自动识别你订阅中的三网优化VPS（IPv4 TCP 节点）作为前置中转，无需手动暴露或填写节点名
 *   2. 追加你独享的美国静态住宅落地节点（IPRoyal-US），并通过 dialer-proxy 串联两跳
 *   3. 将 Claude / Anthropic、风控验证、支付、ipinfo.io 规则置顶并强制走家宽节点
 *   4. 拦截常见 WebRTC STUN 端口（3478 / 19302），防止真实 IP 泄漏
 *   5. 关闭 sniffer 中的 QUIC 嗅探，避免纯 HTTP 家宽（udp: false）异常
 *
 * 使用方法：
 *   1. 先在客户端导入你的三网优化VPS订阅
 *   2. 修改下方【必填配置区】中的家宽 IP、端口、用户名、密码（DIALER_PROXY 保持留空即可自动识别）
 *   3. 在 Clash Verge Rev（订阅 -> 全局扩展脚本）或 Mihomo Party（覆写 -> 新建 JS 覆写并启用）中粘贴本脚本
 *   4. 确保客户端处于「规则模式 (Rule)」并开启「系统代理」
 */

// ==================== 必填配置区（每人独立填写） ====================
const ISP_NAME = 'IPRoyal-US';             // 落地节点名，通常无需修改
const ISP_SERVER = 'xxx.xxx.xxx.xxx';      // 改为你的静态家宽 IP，例如 'xxx.xxx.xxx.xxx'
const ISP_PORT = 12323;                    // 家宽 HTTP 端口（数字）
const ISP_USERNAME = '<填入家宽用户名>';    // 家宽代理账号
const ISP_PASSWORD = '<填入家宽密码>';      // 家宽代理密码

// 【可选·高级】手动指定前置中转节点名；强烈建议保持留空 ''，脚本会自动从当前订阅挑选首个 IPv4 TCP 节点
const DIALER_PROXY = '';
// ===================================================================

const CLAUDE_TOP_RULES = [
  // 1. Claude / Anthropic 核心域名
  `DOMAIN-SUFFIX,claude.ai,${ISP_NAME}`,
  `DOMAIN-SUFFIX,claude.com,${ISP_NAME}`,
  `DOMAIN-SUFFIX,anthropic.com,${ISP_NAME}`,
  `DOMAIN-SUFFIX,claudeusercontent.com,${ISP_NAME}`,
  `DOMAIN-SUFFIX,claudemcpclient.com,${ISP_NAME}`,
  `DOMAIN-SUFFIX,servd-anthropic-website.b-cdn.net,${ISP_NAME}`,

  // 2. 启动脚本出口 IP 校验域名（必须与 Claude 同出口）
  `DOMAIN,ipinfo.io,${ISP_NAME}`,

  // 3. 人机验证 / 风控遥测 / 支付相关域名（防止与主站出口 IP 不一致）
  `DOMAIN-SUFFIX,hcaptcha.com,${ISP_NAME}`,
  `DOMAIN-SUFFIX,challenges.cloudflare.com,${ISP_NAME}`,
  `DOMAIN-SUFFIX,sentry.io,${ISP_NAME}`,
  `DOMAIN-SUFFIX,intercom.io,${ISP_NAME}`,
  `DOMAIN-SUFFIX,intercomcdn.com,${ISP_NAME}`,
  `DOMAIN-SUFFIX,datadoghq.com,${ISP_NAME}`,
  `DOMAIN-SUFFIX,statsig.com,${ISP_NAME}`,
  `DOMAIN-SUFFIX,statsigapi.net,${ISP_NAME}`,
  `DOMAIN-SUFFIX,segment.io,${ISP_NAME}`,
  `DOMAIN-SUFFIX,segment.com,${ISP_NAME}`,
  `DOMAIN-SUFFIX,stripe.com,${ISP_NAME}`,
  `DOMAIN-SUFFIX,stripe.network,${ISP_NAME}`,

  // 4. Apple 登录 / 订阅认证域名
  `DOMAIN,appleid.apple.com,${ISP_NAME}`,
  `DOMAIN,idmsa.apple.com,${ISP_NAME}`,
  `DOMAIN,appleid.cdn-apple.com,${ISP_NAME}`,
  `DOMAIN,gsa.apple.com,${ISP_NAME}`,

  // 5. 拦截常见 STUN 端口，防止浏览器 WebRTC 泄漏真实 IP
  'DST-PORT,3478,REJECT',
  'DST-PORT,19302,REJECT',
];

function resolveDialerProxy(config) {
  const proxies = Array.isArray(config.proxies)
    ? config.proxies.filter((p) => p && p.name && p.name !== ISP_NAME)
    : [];
  const groups = Array.isArray(config['proxy-groups'])
    ? config['proxy-groups'].filter((g) => g && g.name)
    : [];

  // 若用户手动指定了前置节点名，则优先校验并使用
  const manual = String(DIALER_PROXY || '').trim();
  if (manual) {
    if (!config['proxy-providers'] && proxies.length > 0) {
      const names = new Set([...proxies.map((p) => p.name), ...groups.map((g) => g.name)]);
      if (!names.has(manual)) {
        throw new Error(`未在当前订阅中找到前置节点 "${manual}"，建议将 DIALER_PROXY 留空以自动识别`);
      }
    }
    return manual;
  }

  // 自动识别模式：优先挑选订阅中首个 IPv4 的 TCP 协议节点（排除 HY2 / TUIC / IPv6 节点）
  const tcpTypes = new Set(['vless', 'trojan', 'vmess', 'ss', 'ssr']);
  const isIpv6Server = (srv) => typeof srv === 'string' && srv.includes(':');
  const isV6OrUdpName = (name) => /(^|[-_\s])(v6|ipv6|hy2|hysteria|tuic)\b/i.test(String(name));

  const preferred = proxies.find(
    (p) =>
      tcpTypes.has(String(p.type || '').toLowerCase()) &&
      !isIpv6Server(p.server) &&
      !isV6OrUdpName(p.name)
  );
  if (preferred) return preferred.name;

  // 次选：任意非纯 UDP（hysteria/tuic）节点
  const nonUdp = proxies.find(
    (p) => !['hysteria', 'hysteria2', 'tuic'].includes(String(p.type || '').toLowerCase())
  );
  if (nonUdp) return nonUdp.name;

  // 再次选：首个可用节点
  if (proxies.length > 0) return proxies[0].name;

  // 兜底（若订阅采用 proxy-providers 远程集合）：选首个手动/节点选择策略组
  const selectGroup =
    groups.find((g) => g.type === 'select' && /手动|节点|proxy|select/i.test(g.name)) ||
    groups.find((g) => g.type === 'select') ||
    groups[0];
  if (selectGroup) return selectGroup.name;

  throw new Error('未能从当前订阅自动识别到三网优化VPS前置节点，请确认已导入订阅或手动填写 DIALER_PROXY');
}

function main(config) {
  if (!config || typeof config !== 'object') {
    return config;
  }

  // 基础参数检查，避免忘记替换占位符导致静默失效
  if (
    !ISP_SERVER ||
    ISP_SERVER.includes('<') ||
    /x{2,}/i.test(ISP_SERVER) ||
    !ISP_USERNAME ||
    ISP_USERNAME.includes('<') ||
    !ISP_PASSWORD ||
    ISP_PASSWORD.includes('<')
  ) {
    throw new Error('请先在 mihomo-override.js 顶部填写你自己的家宽 IP、端口、用户名和密码');
  }

  if (!Array.isArray(config.proxies)) {
    config.proxies = [];
  }

  const dialerName = resolveDialerProxy(config);

  // 1. 注入静态家宽节点（先去重，且不加入任何自动测速/手动选择组，避免浪费家宽流量）
  config.proxies = config.proxies.filter((p) => p && p.name !== ISP_NAME);
  config.proxies.push({
    name: ISP_NAME,
    type: 'http',
    server: ISP_SERVER,
    port: Number(ISP_PORT),
    username: String(ISP_USERNAME),
    password: String(ISP_PASSWORD),
    'dialer-proxy': dialerName,
    udp: false,
  });

  // 2. 将 Claude 与防泄漏规则置顶（先去重再 unshift 到最前面，确保最高优先级）
  if (!Array.isArray(config.rules)) {
    config.rules = [];
  }
  const topSet = new Set(CLAUDE_TOP_RULES);
  config.rules = config.rules.filter((r) => !topSet.has(r));
  config.rules.unshift(...CLAUDE_TOP_RULES);

  // 3. 关闭 sniffer 中的 QUIC 嗅探（适配纯 HTTP udp:false 家宽）
  if (config.sniffer && config.sniffer.sniff && config.sniffer.sniff.quic) {
    delete config.sniffer.sniff.quic;
  }

  return config;
}
