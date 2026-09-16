const sensitive =
  /password|passwd|secret|token|authorization|cookie|csrf|api.?key/i;
export class Redactor {
  values: string[] = [];
  constructor(secrets: unknown) {
    const visit = (v: any, key = "") => {
      if (typeof v === "string" && sensitive.test(key)) this.add(v);
      else if (Array.isArray(v)) {
        if (/cookies/i.test(key)) {
          for (const cookie of v)
            if (typeof cookie?.value === "string") this.add(cookie.value);
        } else v.forEach((x) => visit(x, key));
      } else if (v && typeof v === "object") {
        if (key === "storageState") {
          const state = v as {
            cookies?: Array<{ value?: string }>;
            origins?: Array<{
              localStorage?: Array<{ name?: string; value?: string }>;
            }>;
          };
          for (const cookie of state.cookies || [])
            if (cookie.value) this.add(cookie.value);
          for (const origin of state.origins || [])
            for (const entry of origin.localStorage || [])
              if (entry.value && sensitive.test(entry.name || ""))
                this.add(entry.value);
          return;
        }
        for (const [k, x] of Object.entries(v))
          visit(x, sensitive.test(key) ? key : k);
      }
    };
    visit(secrets);
  }
  add(value: string) {
    if (value.length >= 4 && !this.values.includes(value))
      this.values.push(value);
  }
  text(value: string) {
    let s = value;
    try {
      const parsed = JSON.parse(s);
      if (parsed && typeof parsed === "object")
        return JSON.stringify(this.clean(parsed));
    } catch {}
    // Learn secrets in opaque HTML and JSON before evidence is persisted.
    s = s.replace(
      /((?:name|id)=["'][^"']*(?:password|token|secret|csrf|api.?key)[^"']*["'][^>]*\bvalue=)(["'])([^"']*)\2/gi,
      (_m, p, q, v) => {
        this.add(v);
        return p + q + "[REDACTED]" + q;
      },
    );
    s = s.replace(
      /(["'](?:[^"']*(?:password|token|secret|csrf|api.?key)[^"']*)["']\s*:\s*)(["'])([^"']*)\2/gi,
      (_m, p, q, v) => {
        this.add(v);
        return p + q + "[REDACTED]" + q;
      },
    );
    for (const v of this.values.sort((a, b) => b.length - a.length)) {
      s = s
        .split(v)
        .join("[REDACTED]")
        .split(encodeURIComponent(v))
        .join("[REDACTED]");
    }
    return s
      .replace(/(Bearer\s+)[\w.+\/-]+/gi, "$1[REDACTED]")
      .replace(
        /((?:password|token|secret|csrf|api_key)=)[^&\s"<>]+/gi,
        "$1[REDACTED]",
      );
  }
  clean<T>(value: T): T {
    if (typeof value === "string") return this.text(value) as T;
    if (Array.isArray(value)) return value.map((x) => this.clean(x)) as T;
    if (value && typeof value === "object")
      return Object.fromEntries(
        Object.entries(value).map(([k, v]) => {
          if (sensitive.test(k)) {
            if (typeof v === "string") this.add(v);
            return [k, "[REDACTED]"];
          }
          return [k, this.clean(v)];
        }),
      ) as T;
    return value;
  }
  url(url: string) {
    try {
      const u = new URL(url);
      for (const k of [...u.searchParams.keys()])
        if (sensitive.test(k)) {
          this.add(u.searchParams.get(k) || "");
          u.searchParams.set(k, "[REDACTED]");
        }
      return this.text(u.toString());
    } catch {
      return this.text(url);
    }
  }
}
