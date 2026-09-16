import { randomUUID } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { BrowserRecorder } from "./browser.js";
import { dangerous, inScope } from "./config.js";
import { mapZapAlert } from "./asvs.js";
import type { Redactor } from "./redact.js";
import type { Evidence, Finding, ProjectConfig, ScanData } from "./types.js";

const now = () => new Date().toISOString();
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const regexEscape = (value: string) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Broad, interpreter-focused ZAP rules. The list intentionally excludes denial of
// service and brute-force scanners. A project can replace it with scannerIds.
export const DEEP_SCANNER_IDS = Object.freeze([
  "6", // path traversal
  "7", // remote file inclusion
  "40003", // CRLF injection
  "40009", // server-side include
  "40012", // reflected XSS
  "40014", // persistent XSS
  "40016",
  "40017", // cross-site scripting variants
  "40018",
  "40019",
  "40020",
  "40021",
  "40022",
  "40024", // SQL injection variants
  "40028", // ELMAH information leak
  "40046", // SSRF
  "90019", // server-side code injection
  "90020", // OS command injection
  "90021", // XPath injection
  "90023", // XXE
  "90033", // NoSQL injection
  "90035", // server-side template injection
]);

type ActiveTarget = {
  url: string;
  method: "GET" | "POST";
  postData?: string;
  contentType?: string;
  headers?: Record<string, string>;
};

export function activeScanSettings(config: ProjectConfig) {
  const configured = config.tests?.activeScan;
  const profile = configured?.profile ?? "xss";
  return {
    profile,
    role: configured?.role,
    attackStrength:
      configured?.attackStrength ?? (profile === "deep" ? "MEDIUM" : "LOW"),
    scannerIds: configured?.scannerIds.length
      ? configured.scannerIds
      : profile === "deep"
        ? [...DEEP_SCANNER_IDS]
        : ["40012"],
    methods: configured?.methods ?? (["GET"] as Array<"GET" | "POST">),
    includePathEndpoints:
      configured?.includePathEndpoints ?? profile === "deep",
    maxEndpoints: configured?.maxEndpoints ?? config.limits.statesPerRole,
    discoveryPaths: configured?.discoveryPaths ?? [],
  };
}
export function allowedActiveUrl(config: ProjectConfig, url: string): boolean {
  if (!inScope(config, url)) return false;
  try {
    return !dangerous.test(decodeURIComponent(new URL(url).pathname));
  } catch {
    return false;
  }
}

export function interactiveActiveCandidate(evidence: Evidence): boolean {
  if (!evidence.url || evidence.method !== "GET") return false;
  const url = new URL(evidence.url);
  if (!url.search) return false;
  if (
    /\.(?:css|js|mjs|map|woff2?|ttf|eot|png|jpe?g|gif|svg|ico|webp|avif|mp4|webm|pdf|zip)$/i.test(
      url.pathname,
    )
  )
    return false;
  const contentType = evidence.responseHeaders?.["content-type"] || "";
  if (
    contentType &&
    !/(?:text\/html|application\/(?:json|xml)|text\/plain)/i.test(contentType)
  )
    return false;
  return [...url.searchParams.keys()].some(
    (key) => !/^(?:_|id|v|ver|version|hash|cache|cb|timestamp)$/i.test(key),
  );
}

function activeContentType(evidence: Evidence): boolean {
  const contentType = evidence.responseHeaders?.["content-type"] || "";
  return (
    !contentType ||
    /(?:text\/html|application\/(?:json|xml)|text\/plain)/i.test(contentType)
  );
}

/** Select one representative request for each method/path/input-name shape.
 * Deep mode keeps path-only pages and explicitly allowed POST samples, while the
 * legacy XSS profile retains its query-only behavior. */
export function selectActiveTargets(
  config: ProjectConfig,
  evidence: Evidence[],
): ActiveTarget[] {
  const settings = activeScanSettings(config);
  const targets = new Map<string, ActiveTarget>();
  for (const item of evidence) {
    if (!item.url || !item.method || !allowedActiveUrl(config, item.url))
      continue;
    // Persisted evidence is for reporting, not a source of replayable secrets.
    // Never submit masked values as if they were valid session/CSRF state.
    if (
      /\[REDACTED\]|%5BREDACTED%5D/i.test(item.url + (item.requestBody || ""))
    )
      continue;
    const method = item.method.toUpperCase();
    if (!settings.methods.includes(method as "GET" | "POST")) continue;
    const url = new URL(item.url);
    if (
      /\.(?:css|js|mjs|map|woff2?|ttf|eot|png|jpe?g|gif|svg|ico|webp|avif|mp4|webm|pdf|zip)$/i.test(
        url.pathname,
      ) ||
      !activeContentType(item)
    )
      continue;
    if (method === "GET") {
      if (!settings.includePathEndpoints && !interactiveActiveCandidate(item))
        continue;
      const keys = [...url.searchParams.keys()].sort().join("&");
      targets.set(`GET ${url.pathname}?${keys}`, {
        url: item.url,
        method: "GET",
        headers: item.requestHeaders,
      });
      continue;
    }
    if (
      method === "POST" &&
      config.allowedActions.includes(decodeURIComponent(url.pathname)) &&
      item.requestBody
    ) {
      const contentType = item.requestHeaders?.["content-type"] || "";
      if (
        !/(?:application\/x-www-form-urlencoded|application\/json|multipart\/form-data)/i.test(
          contentType,
        )
      )
        continue;
      let shape = item.requestBody;
      if (/application\/x-www-form-urlencoded/i.test(contentType))
        shape = [...new URLSearchParams(item.requestBody).keys()]
          .sort()
          .join("&");
      else if (/multipart\/form-data/i.test(contentType)) {
        // File uploads need a dedicated workflow. Text form parts can be scanned
        // in their original encoding, including Laravel's hidden CSRF token.
        if (/Content-Disposition:[^\r\n]*filename=/i.test(item.requestBody))
          continue;
        shape = [
          ...item.requestBody.matchAll(
            /Content-Disposition:[^\r\n]*\bname="([^"]+)"/gi,
          ),
        ]
          .map((m) => m[1])
          .sort()
          .join("&");
        if (!shape) continue;
      } else {
        try {
          shape = Object.keys(JSON.parse(item.requestBody)).sort().join("&");
        } catch {
          continue;
        }
      }
      targets.set(`POST ${url.pathname}?${shape}`, {
        url: item.url,
        method: "POST",
        postData: item.requestBody,
        contentType,
        headers: item.requestHeaders,
      });
    }
  }
  for (const path of settings.discoveryPaths) {
    const url = new URL(path, config.target).href;
    if (allowedActiveUrl(config, url))
      targets.set(`GET ${new URL(url).pathname}?`, { url, method: "GET" });
  }
  return [...targets.values()].slice(0, settings.maxEndpoints);
}

/** No credentials are embedded in the uploaded script. Auth material is held in ZAP memory only.
 * A blocked message is assigned an unsupported transport scheme, which the HTTP sender rejects
 * before opening a connection. Throwing from a ZAP script alone is NOT a request blocker. */
export function buildZapGuardScript(
  config: ProjectConfig,
  key: string,
): string {
  const target = new URL(config.target);
  const active = activeScanSettings(config);
  return `var Vars=Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var URI=Java.type('org.apache.commons.httpclient.URI');
var JURI=Java.type('java.net.URI');
var Thread=Java.type('java.lang.Thread');
var Lock=Java.type('java.util.concurrent.locks.ReentrantLock');
var lock=new Lock(); var next=0;
var settings=${JSON.stringify({ key, scheme: target.protocol.slice(0, -1), host: target.hostname, port: Number(target.port) || (target.protocol === "https:" ? 443 : 80), include: config.includePaths, exclude: config.excludePaths, rps: config.limits.requestsPerSecond, deadline: Date.now() + config.limits.minutes * 60000, methods: active.methods, mutations: config.allowedActions })};
function allowed(raw){try{var u=new JURI(String(raw));var scheme=String(u.getScheme()||'').toLowerCase();var port=u.getPort();if(port<0)port=scheme==='https'?443:80;var path=decodeURIComponent(String(u.getRawPath()||'/'));return !u.getRawUserInfo()&&scheme===settings.scheme&&String(u.getHost()||'').toLowerCase()===settings.host.toLowerCase()&&port===settings.port&&settings.include.some(function(p){return path.indexOf(p)===0})&&!settings.exclude.some(function(p){return path.indexOf(p)===0})&&!/(?:logout|log.out|sign.out|delete|remove|destroy|pay(?:ment)?|checkout|refund|send.?email|reset)/i.test(path);}catch(e){return false;}}
function blocked(msg,reason){msg.getRequestHeader().setHeader('Cookie',null);msg.getRequestHeader().setHeader('Authorization',null);msg.getRequestHeader().setURI(new URI('flowaudit-blocked://local/'+reason,true));Vars.setGlobalVar(settings.key+'.blocked',String(Number(Vars.getGlobalVar(settings.key+'.blocked')||0)+1));}
function sendingRequest(msg,initiator,helper){
  msg.getRequestHeader().setHeader('x-flowaudit-correlation',null);
  msg.getRequestHeader().setHeader('x-security-scan-correlation',null);
  if(initiator!==2&&initiator!==6)return;
  lock.lock();
  try{
    var raw=String(msg.getRequestHeader().getURI());
    var alive=Number(Vars.getGlobalVar(settings.key+'.alive')||0);
    var method=String(msg.getRequestHeader().getMethod()).toUpperCase();var pathname=decodeURIComponent(String(new JURI(raw).getRawPath()||'/'));
    if(!allowed(raw)||settings.methods.indexOf(method)<0||(method!=='GET'&&settings.mutations.indexOf(pathname)<0)){blocked(msg,'scope');return;}
    if(Date.now()>settings.deadline||Date.now()-alive>5000){blocked(msg,'expired');return;}
    var wait=next-Date.now();if(wait>0)Thread.sleep(Math.ceil(wait));next=Date.now()+1000/settings.rps;
    if(Date.now()-Number(Vars.getGlobalVar(settings.key+'.alive')||0)>5000){blocked(msg,'expired');return;}
    var auth=JSON.parse(String(Vars.getGlobalVar(settings.key+'.auth')||'{}'));
    var u=new JURI(raw);var path=String(u.getPath()||'/');var domain=String(u.getHost());
    var cookies=(auth.cookies||[]).filter(function(c){var d=c.domain.charAt(0)==='.'?c.domain.slice(1):c.domain;return (domain===d||(c.domain.charAt(0)==='.'&&domain.endsWith('.'+d)))&&(path===c.path||path.indexOf(c.path.endsWith('/')?c.path:c.path+'/')===0)&&(!c.secure||String(u.getScheme())==='https')&&(c.expires===-1||!c.expires||c.expires*1000>Date.now())});
    msg.getRequestHeader().setHeader('Cookie',cookies.length?cookies.map(function(c){return c.name+'='+c.value}).join('; '):null);
    msg.getRequestHeader().setHeader('Authorization',auth.bearer?'Bearer '+auth.bearer:null);
  }catch(e){blocked(msg,'guard-error');Vars.setGlobalVar(settings.key+'.error','Scope guard failed');}finally{lock.unlock();}
}
function responseReceived(msg,initiator,helper){
  if(initiator!==2&&initiator!==6)return;
  try{var location=msg.getResponseHeader().getHeader('Location');if(location){var resolved=new JURI(String(msg.getRequestHeader().getURI())).resolve(String(location));if(!allowed(String(resolved))){msg.getResponseHeader().setHeader('Location',null);Vars.setGlobalVar(settings.key+'.blocked',String(Number(Vars.getGlobalVar(settings.key+'.blocked')||0)+1));}}}catch(e){msg.getResponseHeader().setHeader('Location',null);}
}`;
}

type ZapMessage = {
  id?: string;
  timestamp?: string;
  requestHeader?: string;
  requestBody?: string;
  responseHeader?: string;
  responseBody?: string;
};
type ZapAlert = {
  id: string;
  pluginId: string;
  name?: string;
  alert?: string;
  risk?: string;
  url: string;
  method?: string;
  param?: string;
  attack?: string;
  evidence?: string;
  description?: string;
  solution?: string;
  messageId?: string;
};
function headers(raw = ""): Record<string, string> {
  return Object.fromEntries(
    raw
      .split(/\r?\n/)
      .slice(1)
      .filter((line) => line.includes(":"))
      .map((line) => {
        const index = line.indexOf(":");
        return [
          line.slice(0, index).toLowerCase(),
          line.slice(index + 1).trim(),
        ];
      }),
  );
}

export class ZapAdapter {
  private initialized = false;
  private initialization?: Promise<void>;
  private currentScan?: string;
  private guard?: string;
  private guardKey?: string;
  private context?: string;
  private contextName?: string;
  private policy?: string;
  private enabledScanners: string[] = [];
  private cancelled = false;
  private running = false;
  private lastProbe = 0;
  private activeRole?: string;
  constructor(
    public config: ProjectConfig,
    public data: ScanData,
    public recorder: BrowserRecorder,
    public redactor: Redactor,
    public save: () => void,
  ) {}
  /** Prepare the configured DEDICATED ZAP instance before opening any browser session.
   * Starts an unsaved session so old HTTP messages/alert deduplication cannot contaminate a scan.
   * Safe to call repeatedly/concurrently on this adapter; run() never resets captured history. */
  async initialize(): Promise<void> {
    if (this.initialized) return;
    if (this.initialization) return this.initialization;
    if (
      this.data.screens.length ||
      this.data.evidence.length ||
      this.recorder.sessions.size
    )
      throw Error(
        "Initialize the dedicated ZAP session before opening browser roles or capturing evidence",
      );
    this.initialization = (async () => {
      await this.api("ascan", "action", "stopAllScans");
      await this.api("core", "action", "newSession", {
        name: "",
        overwrite: "true",
      });
      // A crashed earlier worker can leave an expired guard and its in-memory credentials.
      // Clean only flowaudit resources; unrelated scripts and policies are left intact.
      const scripts = await this.api("script", "view", "listScripts");
      for (const script of scripts.listScripts ?? [])
        if (/^(?:flowaudit|security-scan)-[a-f0-9-]{36}$/.test(script.name))
          await this.api("script", "action", "remove", {
            scriptName: script.name,
          });
      const vars = await this.api("script", "view", "globalVars");
      for (const key of Object.keys(vars.globalVars ?? {}))
        if (/^ss-[a-f0-9]{16}\.(?:auth|alive|blocked|error)$/.test(key))
          await this.api("script", "action", "clearGlobalVar", { varKey: key });
      const policies = await this.api("ascan", "view", "scanPolicyNames");
      for (const policy of policies.scanPolicyNames ?? [])
        if (/^(?:flowaudit|security-scan)-[a-f0-9-]{36}$/.test(policy))
          await this.api("ascan", "action", "removeScanPolicy", {
            scanPolicyName: policy,
          });
      if (activeScanSettings(this.config).methods.includes("POST")) {
        const names = await this.api("acsrf", "view", "optionTokensNames");
        for (const token of [
          "_token",
          "csrf",
          "csrf_token",
          "__RequestVerificationToken",
        ])
          if (!(names.optionTokensNames ?? []).includes(token))
            await this.api("acsrf", "action", "addOptionToken", {
              String: token,
            });
      }
      this.initialized = true;
    })();
    try {
      await this.initialization;
    } finally {
      this.initialization = undefined;
    }
  }
  private check() {
    if (this.cancelled || this.data.status !== "running")
      throw Error("ZAP scan cancelled");
    if (
      Date.now() - Date.parse(this.data.startedAt) >
      this.config.limits.minutes * 60000
    )
      throw Error("ZAP scan time budget reached");
  }
  private async api(
    component: string,
    type: string,
    name: string,
    params: Record<string, string> = {},
  ): Promise<any> {
    const config = this.config.zap;
    if (!config) throw Error("ZAP is not configured");
    const key = process.env[config.apiKeyEnv];
    if (!key)
      throw Error(
        `Missing ZAP API key environment variable: ${config.apiKeyEnv}`,
      );
    this.redactor.add(key);
    const format = type === "other" ? "OTHER" : "JSON";
    const endpoint = new URL(
      `/${format}/${component}/${type}/${name}/`,
      config.apiUrl,
    );
    const encoded = new URLSearchParams({ ...params, apikey: key }).toString();
    // Node fetch rewrites Host; ZAP's reserved "zap" host selects the API instead of proxying.
    const response = await new Promise<{ status: number; text: string }>(
      (resolve, reject) => {
        const send =
          endpoint.protocol === "https:" ? httpsRequest : httpRequest;
        const request = send(
          endpoint,
          {
            method: "POST",
            headers: {
              "content-type": "application/x-www-form-urlencoded",
              Host: process.env.ZAP_API_HOST || "zap",
              "content-length": Buffer.byteLength(encoded),
            },
          },
          (response) => {
            let text = "";
            response.setEncoding("utf8");
            response.on("data", (part) => {
              text += part;
              if (text.length > 16 * 1024 * 1024)
                request.destroy(Error("ZAP API response exceeds 16 MB"));
            });
            response.on("end", () =>
              resolve({ status: response.statusCode || 0, text }),
            );
            response.on("error", reject);
          },
        );
        request.setTimeout(15000, () =>
          request.destroy(Error("ZAP API request timed out")),
        );
        request.on("error", reject);
        request.end(encoded);
      },
    );
    let body: any;
    try {
      body = JSON.parse(response.text);
    } catch {
      throw Error(
        `ZAP ${component}/${name}: invalid API response (${response.status})`,
      );
    }
    if (response.status < 200 || response.status >= 300 || body.code)
      throw Error(
        `ZAP ${component}/${name}: ${body.code || response.status} ${body.message || ""}`,
      );
    return body;
  }
  private async syncAuth(role: string) {
    if (!this.guardKey) return;
    const session = this.recorder.session(role),
      profile = this.config.roles[role];
    const cookies = await session.context.cookies();
    for (const cookie of cookies) this.redactor.add(cookie.value);
    const secret = this.recorder.secrets[profile.secretRef];
    const bearer =
      profile.type === "bearer"
        ? secret?.token
        : profile.type === "storageState"
          ? secret?.bearer
          : undefined;
    if (bearer) this.redactor.add(bearer);
    await this.api("script", "action", "setGlobalVar", {
      varKey: `${this.guardKey}.auth`,
      varValue: JSON.stringify({ cookies, bearer }),
    });
    await this.api("script", "action", "setGlobalVar", {
      varKey: `${this.guardKey}.alive`,
      varValue: String(Date.now()),
    });
  }
  private async guardState() {
    if (!this.guard) return;
    const scripts = await this.api("script", "view", "listScripts");
    const script = scripts.listScripts?.find((s: any) => s.name === this.guard);
    if (
      !script ||
      String(script.enabled) !== "true" ||
      String(script.error) === "true"
    )
      throw Error("ZAP outbound scope guard is not healthy");
    const vars = await this.api("script", "view", "globalVars");
    const error = vars.globalVars?.[`${this.guardKey}.error`];
    if (error) throw Error("ZAP outbound scope guard failed");
  }
  private messageEvidence(
    message: ZapMessage,
    role: string | undefined,
    note: string,
    url?: string,
  ): Evidence {
    const request = message.requestHeader ?? "",
      response = message.responseHeader ?? "";
    const requestUrl = url ?? request.split(/\s+/)[1];
    const evidence = this.redactor.clean({
      id: randomUUID(),
      kind: "http" as const,
      role,
      url: requestUrl,
      method: request.split(/\s+/)[0],
      status: Number(response.split(/\s+/)[1]) || undefined,
      requestHeaders: headers(request),
      responseHeaders: headers(response),
      requestBody: message.requestBody?.slice(0, 20000),
      responseBody: message.responseBody?.slice(0, 20000),
      note,
      at: message.timestamp
        ? new Date(Number(message.timestamp)).toISOString()
        : now(),
    });
    this.data.evidence.push(evidence);
    this.save();
    return evidence;
  }
  private async zapProbe(role: string) {
    const profile = this.config.roles[role],
      url = new URL(profile.probePath, this.config.target);
    if (!allowedActiveUrl(this.config, url.href))
      throw Error("Authentication probe must be a safe URL in scope");
    const result = await this.api("core", "action", "sendRequest", {
      request: `GET ${url.href} HTTP/1.1\r\nHost: ${url.host}\r\nAccept: application/json,text/html\r\nConnection: close\r\n\r\n`,
      followRedirects: "false",
    });
    const message: ZapMessage = result.sendRequest?.[0] ?? {};
    const ok =
      /^HTTP\/\S+ 200\b/.test(message.responseHeader ?? "") &&
      (message.responseBody ?? "").includes(profile.probeContains);
    this.messageEvidence(
      message,
      role,
      `Independent ZAP authentication probe: ${ok ? "authenticated" : "failed"}`,
      url.href,
    );
    if (!ok)
      throw Error("ZAP authentication probe failed; active scan stopped");
    await this.guardState();
  }
  private async heartbeat(role: string, force = false) {
    this.check();
    if (this.guardKey)
      await this.api("script", "action", "setGlobalVar", {
        varKey: `${this.guardKey}.alive`,
        varValue: String(Date.now()),
      });
    if (force || Date.now() - this.lastProbe > 3000) {
      if (!(await this.recorder.probe(role)))
        throw Error("Browser authentication expired; ZAP scan stopped");
      await this.syncAuth(role);
      if (this.guard) await this.zapProbe(role);
      this.lastProbe = Date.now();
    }
  }
  private async installGuard(role: string) {
    const suffix = randomUUID();
    this.guard = `flowaudit-${suffix}`;
    // ZAP ScriptVars keys have a 30-character maximum, including the suffix.
    this.guardKey = `ss-${suffix.replaceAll("-", "").slice(0, 16)}`;
    const file = await this.api("core", "other", "fileUpload", {
      fileName: `${this.guard}.js`,
      fileContents: buildZapGuardScript(this.config, this.guardKey),
    });
    if (typeof file.Uploaded !== "string")
      throw Error(
        "ZAP guard upload failed; enable api.filexfer=true on the dedicated ZAP instance",
      );
    await this.api("script", "action", "load", {
      scriptName: this.guard,
      scriptType: "httpsender",
      scriptEngine: "ECMAScript : Graal.js",
      fileName: file.Uploaded,
      scriptDescription:
        "flowaudit scope, rate, credential and cancellation guard",
    });
    await this.syncAuth(role);
    await this.api("script", "action", "enable", { scriptName: this.guard });
    await this.guardState();
  }
  private async configureActive() {
    await this.api("ascan", "action", "setOptionHandleAntiCSRFTokens", {
      Boolean: "true",
    });
    await this.api("ascan", "action", "setOptionExcludeAntiCsrfTokens", {
      Boolean: "true",
    });
    // A single scanning thread avoids consuming one-time tokens concurrently.
    await this.api("ascan", "action", "setOptionThreadPerHost", {
      Integer: "1",
    });
    const name = `flowaudit-${randomUUID()}`;
    this.contextName = name;
    this.policy = name;
    this.context = String(
      (await this.api("context", "action", "newContext", { contextName: name }))
        .contextId,
    );
    const origin = regexEscape(new URL(this.config.target).origin);
    for (const path of this.config.includePaths)
      await this.api("context", "action", "includeInContext", {
        contextName: name,
        regex: `${origin}${regexEscape(path)}.*`,
      });
    for (const path of this.config.excludePaths)
      await this.api("context", "action", "excludeFromContext", {
        contextName: name,
        regex: `${origin}${regexEscape(path)}.*`,
      });
    await this.api("context", "action", "setContextInScope", {
      contextName: name,
      booleanInScope: "true",
    });
    await this.api("ascan", "action", "addScanPolicy", {
      scanPolicyName: name,
    });
    await this.api("ascan", "action", "disableAllScanners", {
      scanPolicyName: name,
    });
    const settings = activeScanSettings(this.config);
    const inventory = await this.api("ascan", "view", "scanners", {
      scanPolicyName: name,
    });
    const available = new Set<string>(
      (inventory.scanners ?? []).map((scanner: any) =>
        String(scanner.id ?? scanner.pluginId),
      ),
    );
    this.enabledScanners = available.size
      ? settings.scannerIds.filter((id) => available.has(id))
      : settings.scannerIds;
    if (!this.enabledScanners.length)
      throw Error(
        "None of the configured ZAP active scanner rules are installed",
      );
    await this.api("ascan", "action", "enableScanners", {
      ids: this.enabledScanners.join(","),
      scanPolicyName: name,
    });
    for (const id of this.enabledScanners)
      await this.api("ascan", "action", "setScannerAttackStrength", {
        id,
        attackStrength: settings.attackStrength,
        scanPolicyName: name,
      });
  }
  private async drainPassive(role: string) {
    while (true) {
      await this.heartbeat(role);
      const result = await this.api("pscan", "view", "recordsToScan");
      if (Number(result.recordsToScan) === 0) return;
      await sleep(500);
    }
  }
  private async collect(role: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    let start = 0;
    const identities: Array<{
      role: string;
      cookies: string[];
      bearer?: string;
    }> = [];
    for (const [name, session] of this.recorder.sessions) {
      const cookies = session.context ? await session.context.cookies() : [];
      const profile = this.config.roles[name];
      identities.push({
        role: name,
        cookies: cookies.map((c) => `${c.name}=${c.value}`),
        bearer:
          profile?.type === "bearer"
            ? this.recorder.secrets[profile.secretRef]?.token
            : undefined,
      });
    }
    while (true) {
      this.check();
      const response = await this.api("core", "view", "alerts", {
        baseurl: new URL(this.config.target).origin,
        start: String(start),
        count: "100",
      });
      const alerts: ZapAlert[] = response.alerts ?? [];
      for (const alert of alerts) {
        if (!inScope(this.config, alert.url) || !alert.messageId) continue;
        let message: ZapMessage;
        try {
          message = (
            await this.api("core", "view", "message", { id: alert.messageId })
          ).message;
        } catch {
          continue;
        }
        if (
          !message?.timestamp ||
          Number(message.timestamp) < Date.parse(this.data.startedAt)
        )
          continue;
        const requestHeaders = headers(message.requestHeader);
        const matches = identities.filter(
          (identity) =>
            identity.cookies.some((cookie) =>
              (requestHeaders.cookie ?? "").split(/;\s*/).includes(cookie),
            ) ||
            (identity.bearer &&
              requestHeaders.authorization === `Bearer ${identity.bearer}`),
        );
        const attributedRole =
          matches.length === 1 ? matches[0].role : undefined;
        const evidence = this.messageEvidence(
          message,
          attributedRole,
          `ZAP alert ${alert.id}: ${alert.name || alert.alert}${attributedRole ? "" : " (role attribution unavailable)"}`,
          alert.url,
        );
        const normalizedUrl = this.redactor.url(alert.url);
        const existing = this.data.findings.find(
          (finding) =>
            finding.source === "zap" &&
            finding.ruleId === String(alert.pluginId) &&
            finding.parameter === (alert.param || "") &&
            finding.role === attributedRole,
        );
        if (existing) {
          existing.evidenceIds = [
            ...new Set([...existing.evidenceIds, evidence.id]),
          ];
          existing.locations = [
            ...new Set([...(existing.locations || []), normalizedUrl]),
          ];
          existing.occurrences = existing.evidenceIds.length;
          if (existing.url !== normalizedUrl) existing.screenId = undefined;
          continue;
        }
        const candidates = attributedRole
          ? this.data.screens.filter(
              (screen) =>
                screen.role === attributedRole &&
                screen.url === this.redactor.url(alert.url),
            )
          : [];
        const risk = (alert.risk ?? "").toLowerCase();
        const severity: Finding["severity"] =
          risk === "high"
            ? "high"
            : risk === "medium"
              ? "medium"
              : risk === "low"
                ? "low"
                : "info";
        const finding = this.redactor.clean({
          id: randomUUID(),
          title: alert.name || alert.alert || `ZAP ${alert.pluginId}`,
          severity,
          status: "needs-review" as const,
          source: "zap" as const,
          ruleId: String(alert.pluginId),
          role: attributedRole,
          url: normalizedUrl,
          parameter: alert.param || "",
          occurrences: 1,
          locations: [normalizedUrl],
          screenId: candidates.length === 1 ? candidates[0].id : undefined,
          evidenceIds: [evidence.id],
          asvsIds: mapZapAlert(alert.pluginId),
          steps: [
            `Inspect ${alert.method || "GET"} ${alert.url}`,
            `Review ZAP parameter ${alert.param || "(not specified)"} and the attached request/response.`,
            `Independently reproduce the suspected behavior before confirming this finding.`,
          ],
          description: `ZAP alert ${alert.id}. ${alert.description || ""}\nScanner evidence: ${alert.evidence || "(none)"}\nRemediation guidance: ${alert.solution || "(none)"}\nScanner output is a triage candidate and does not determine ASVS pass/fail.`,
        });
        this.data.findings.push(finding);
        findings.push(finding);
      }
      this.save();
      if (alerts.length < 100) break;
      start += 100;
    }
    return findings;
  }
  async run(role: string, active: boolean): Promise<Finding[]> {
    if (this.running) throw Error("A ZAP job is already running");
    if (active && this.config.mode !== "active")
      throw Error("Active scan requires an active project profile");
    if (!this.config.roles[role]) throw Error("Unknown role");
    this.running = true;
    const existingFindingIds = new Set(
      this.data.findings.map((finding) => finding.id),
    );
    this.cancelled = false;
    this.activeRole = role;
    const job = {
      id: randomUUID(),
      kind: active ? "zap-active" : "zap-passive",
      status: "running",
      error: undefined as string | undefined,
    };
    this.data.jobs.push(job);
    this.save();
    try {
      this.check();
      await this.api("core", "view", "version");
      if (!this.recorder.sessions.has(role)) await this.recorder.open(role);
      await this.heartbeat(role, true);
      if (active) {
        const settings = activeScanSettings(this.config);
        const evidence = [
          ...this.data.evidence.filter(
            (e) => e.role === role && e.method === "GET",
          ),
          ...[...(this.recorder.liveRequests?.values() ?? [])].filter(
            (e) => e.role === role,
          ),
        ];
        const xss = this.config.tests?.xss;
        if (xss?.role === role) {
          const url = new URL(xss.path, this.config.target);
          url.searchParams.set(xss.parameter, "flowaudit");
          evidence.push({
            id: "configured-xss-target",
            kind: "manual",
            role,
            method: "GET",
            url: url.href,
            responseHeaders: { "content-type": "text/html" },
            at: now(),
          });
        }
        const targets = selectActiveTargets(this.config, evidence).sort(
          (a, b) => Number(b.method === "POST") - Number(a.method === "POST"),
        );
        if (targets.length === 0) {
          this.data.coverage.notes.push(
            `ZAP active scan skipped for ${role}: no observed or explicitly configured endpoint was eligible for profile ${settings.profile}. Static assets, disallowed methods and non-allowlisted mutations are excluded.`,
          );
          this.save();
        } else {
          await this.installGuard(role);
          await this.configureActive();
          await this.heartbeat(role, true);
          this.data.coverage.notes.push(
            `ZAP active coverage for ${role}: ${targets.length} deduplicated request shapes; profile ${settings.profile}; ${this.enabledScanners.length} rules (${this.enabledScanners.join(", ")}); strength ${settings.attackStrength}; methods ${settings.methods.join(", ")}. POST is eligible only for exact allowedActions paths with an observed body.`,
          );
          this.save();
          for (const candidate of targets) {
            await this.heartbeat(role, true);
            const target = new URL(candidate.url);
            const requestHeaders = [
              `${candidate.method} ${target.href} HTTP/1.1`,
              `Host: ${target.host}`,
              ...(candidate.contentType
                ? [`Content-Type: ${candidate.contentType}`]
                : []),
              ...Object.entries(candidate.headers || {})
                .filter(
                  ([name, value]) =>
                    [
                      "accept",
                      "x-requested-with",
                      "referer",
                      "origin",
                    ].includes(name.toLowerCase()) &&
                    !/[\r\n]/.test(value) &&
                    (!["referer", "origin"].includes(name.toLowerCase()) ||
                      inScope(this.config, value)),
                )
                .map(([name, value]) => `${name}: ${value}`),
              ...(candidate.postData
                ? [`Content-Length: ${Buffer.byteLength(candidate.postData)}`]
                : []),
              "Connection: close",
              "",
              candidate.postData || "",
            ].join("\r\n");
            // POST already exists in ZAP history from an actual browser submit.
            // Do not replay a potentially consumed token or create a duplicate seed.
            if (candidate.method === "GET")
              await this.api("core", "action", "sendRequest", {
                request: requestHeaders,
                followRedirects: "false",
              });
            this.currentScan = String(
              (
                await this.api("ascan", "action", "scan", {
                  url: target.href,
                  recurse: "false",
                  inScopeOnly: "true",
                  scanPolicyName: this.policy!,
                  method: candidate.method,
                  ...(candidate.postData
                    ? { postData: candidate.postData }
                    : {}),
                  contextId: this.context!,
                })
              ).scan,
            );
            while (true) {
              await this.heartbeat(role);
              const progress = await this.api("ascan", "view", "status", {
                scanId: this.currentScan,
              });
              if (Number(progress.status) >= 100) break;
              await sleep(500);
            }
            this.currentScan = undefined;
            await this.collect(role);
          }
          await this.heartbeat(role, true);
        }
      }
      await this.drainPassive(role);
      await this.collect(role);
      job.status = "completed";
      this.save();
      return this.data.findings.filter(
        (finding) => !existingFindingIds.has(finding.id),
      );
    } catch (error) {
      job.status =
        this.data.status === "interrupted"
          ? "interrupted"
          : this.cancelled || this.data.status === "cancelled"
            ? "cancelled"
            : "failed";
      job.error = this.redactor.text((error as Error).message);
      this.recorder.blocker(job.error, role);
      this.save();
      throw error;
    } finally {
      await this.cleanup();
      this.running = false;
      this.activeRole = undefined;
    }
  }
  private async cleanup() {
    if (this.guardKey)
      await this.api("script", "action", "setGlobalVar", {
        varKey: `${this.guardKey}.alive`,
        varValue: "0",
      }).catch(() => {});
    if (this.guardKey)
      await this.api("script", "action", "clearGlobalVar", {
        varKey: `${this.guardKey}.auth`,
      }).catch(() => {});
    let safeToRemove = !this.currentScan;
    if (this.currentScan) {
      await this.api("ascan", "action", "stop", {
        scanId: this.currentScan,
      }).catch(() => {});
      for (let i = 0; i < 5; i++) {
        try {
          const scans = await this.api("ascan", "view", "scans");
          const scan = scans.scans?.find(
            (s: any) => String(s.id) === this.currentScan,
          );
          if (
            !scan ||
            Number(scan.progress) >= 100 ||
            /^(?:FINISHED|STOPPED)$/i.test(scan.state || "")
          ) {
            safeToRemove = true;
            break;
          }
        } catch {
          break;
        }
        await sleep(250);
      }
    }
    if (this.guard && safeToRemove)
      await this.api("script", "action", "remove", {
        scriptName: this.guard,
      }).catch(() => {});
    if (this.guard && !safeToRemove)
      this.recorder.blocker(
        "ZAP stop could not be verified. Expired outbound guard retained; restart the dedicated ZAP instance before another active scan.",
        this.activeRole,
      );
    if (this.guardKey)
      for (const suffix of ["auth", "alive", "blocked", "error"])
        await this.api("script", "action", "clearGlobalVar", {
          varKey: `${this.guardKey}.${suffix}`,
        }).catch(() => {});
    if (this.contextName)
      await this.api("context", "action", "removeContext", {
        contextName: this.contextName,
      }).catch(() => {});
    if (this.policy)
      await this.api("ascan", "action", "removeScanPolicy", {
        scanPolicyName: this.policy,
      }).catch(() => {});
    this.currentScan =
      this.guard =
      this.guardKey =
      this.context =
      this.contextName =
      this.policy =
        undefined;
  }
  async stop() {
    this.cancelled = true;
    if (this.guardKey)
      await this.api("script", "action", "setGlobalVar", {
        varKey: `${this.guardKey}.alive`,
        varValue: "0",
      }).catch(() => {});
    if (this.currentScan)
      await this.api("ascan", "action", "stop", {
        scanId: this.currentScan,
      }).catch(() => {});
  }
}
