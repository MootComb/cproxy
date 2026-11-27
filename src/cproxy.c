#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>

#define BUF_REQ      131072
#define BUF_RESP     4194304
#define MAX_RULES    256
#define MAX_SNIPPETS 64

typedef struct {
    char type[16];
    char match[512];
    char action[16];
    char path[512];
    char value[512];
    int  kill_ws;
} rule_t;

typedef struct {
    char path[512];
    char *data;
    size_t len;
} snippet_t;

static rule_t g_rules[MAX_RULES];
static int    g_rule_count = 0;

static snippet_t g_snips[MAX_SNIPPETS];
static int       g_snip_count = 0;

static char   g_my_ip[64];
static int    g_port = 8080;

static void copy_trunc(char *dst, size_t dstsz, const char *src) {
    size_t l = strlen(src);
    if (l >= dstsz) l = dstsz - 1;
    memcpy(dst, src, l);
    dst[l] = 0;
}

__attribute__((format(printf, 1, 2)))
static void logmsg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[cproxy] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

static ssize_t read_until_headers(int fd, char *buf, size_t cap) {
    if (cap == 0) return -1;
    buf[0] = 0;
    size_t got = 0;
    while (got < cap - 1) {
        ssize_t r = recv(fd, buf + got, cap - 1 - got, 0);
        if (r <= 0) {
            buf[got] = 0;
            return r == 0 ? (ssize_t)got : -1;
        }
        got += (size_t)r;
        buf[got] = 0;
        if (strstr(buf, "\r\n\r\n")) return (ssize_t)got;
    }
    return -1;
}

static int read_exact(int fd, char *buf, size_t need) {
    size_t got = 0;
    while (got < need) {
        ssize_t r = recv(fd, buf + got, need - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static int write_full(int fd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static char *hdr_find(char *headers, const char *name, size_t *out_len) {
    size_t nl = strlen(name);
    char *p = headers;
    while ((p = strchr(p, '\r'))) {
        if (p[1] != '\n') { p++; continue; }
        char *ln = p + 2;
        if (ln[0] == '\r' && ln[1] == '\n') return NULL;
        if (strncasecmp(ln, name, nl) == 0 && ln[nl] == ':') {
            char *v = ln + nl + 1;
            while (*v == ' ' || *v == '\t') v++;
            char *e = strstr(v, "\r\n");
            if (!e) return NULL;
            if (out_len) *out_len = (size_t)(e - v);
            return v;
        }
        p += 2;
        if (p[0] == '\r' && p[1] == '\n') return NULL;
    }
    return NULL;
}

static void hdr_remove(char *buf, size_t *len, const char *name) {
    char *p = buf;
    while ((p = strchr(p, '\r'))) {
        if (p[1] != '\n') { p++; continue; }
        char *ln = p + 2;
        if (ln[0] == '\r' && ln[1] == '\n') return;
        size_t nl = strlen(name);
        if (strncasecmp(ln, name, nl) == 0 && ln[nl] == ':') {
            char *e = strstr(ln, "\r\n");
            if (!e) return;
            e += 2;
            size_t cut = (size_t)(e - ln);
            memmove(ln, e, (*len) - (size_t)(e - buf));
            *len -= cut;
            buf[*len] = 0;
            return;
        }
        p += 2;
        if (p[0] == '\r' && p[1] == '\n') return;
    }
}

static void hdr_set(char *buf, size_t cap, size_t *len, const char *name, const char *val) {
    hdr_remove(buf, len, name);
    char *he = strstr(buf, "\r\n\r\n");
    if (!he) return;
    size_t ins = (size_t)(he - buf) + 2;
    char line[1024];
    int ll = snprintf(line, sizeof(line), "%s: %s\r\n", name, val);
    if (ll <= 0) return;
    size_t llu = (size_t)ll;
    if (*len + llu >= cap) return;
    memmove(buf + ins + llu, buf + ins, (*len) - ins);
    memcpy(buf + ins, line, llu);
    *len += llu;
    buf[*len] = 0;
}

static void hdr_force_close(char *buf, size_t cap, size_t *len) {
    hdr_remove(buf, len, "Connection");
    hdr_remove(buf, len, "Keep-Alive");
    hdr_set(buf, cap, len, "Connection", "close");
}

static void substitute(char *dst, size_t dstsz, const char *src) {
    const char *tag = "<MY_IP>";
    size_t tl = strlen(tag);
    size_t out = 0;
    const char *p = src;
    while (*p && out + 1 < dstsz) {
        if (strncmp(p, tag, tl) == 0) {
            size_t il = strlen(g_my_ip);
            if (out + il >= dstsz) break;
            memcpy(dst + out, g_my_ip, il);
            out += il;
            p += tl;
        } else {
            dst[out++] = *p++;
        }
    }
    dst[out] = 0;
}

static char *skip_ws(char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

static char *json_value_end(char *v) {
    if (*v == '"') {
        v++;
        while (*v && *v != '"') {
            if (*v == '\\' && v[1]) v++;
            v++;
        }
        return *v == '"' ? v + 1 : v;
    }
    if (*v == '{' || *v == '[') {
        int depth = 1;
        char open = *v;
        char close = (open == '{') ? '}' : ']';
        v++;
        while (*v && depth) {
            if (*v == '"') {
                v++;
                while (*v && *v != '"') {
                    if (*v == '\\' && v[1]) v++;
                    v++;
                }
                if (*v == '"') v++;
                continue;
            }
            if (*v == open) depth++;
            else if (*v == close) depth--;
            v++;
        }
        return v;
    }
    while (*v && *v != ',' && *v != '}' && *v != ']' && *v != '\r' && *v != '\n') v++;
    return v;
}

static int json_patch_key(char *body, size_t cap, size_t *blen,
                          const char *key, const char *newval) {
    char pat[600];
    int pl = snprintf(pat, sizeof(pat), "\"%s\"", key);
    if (pl <= 0) return 0;
    size_t plu = (size_t)pl;

    char *p = body;
    while ((p = strstr(p, pat)) != NULL) {
        char *c = p + plu;
        c = skip_ws(c);
        if (*c != ':') { p = c; continue; }
        c++;
        c = skip_ws(c);
        char *vend = json_value_end(c);
        if (!vend || vend <= c) { p = c; continue; }

        size_t oldlen = (size_t)(vend - c);
        size_t newlen = strlen(newval);
        if (newlen > oldlen) {
            size_t grow = newlen - oldlen;
            if (*blen + grow + 1 > cap) return 0;
            memmove(vend + grow, vend, (*blen) - (size_t)(vend - body) + 1);
            memcpy(c, newval, newlen);
            *blen += grow;
        } else if (newlen < oldlen) {
            size_t shr = oldlen - newlen;
            memmove(c + newlen, vend, (*blen) - (size_t)(vend - body) + 1);
            *blen -= shr;
            if (newlen) memcpy(c, newval, newlen);
        } else {
            memcpy(c, newval, newlen);
        }
        return 1;
    }
    return 0;
}

static int json_patch_wildcard(char *body, size_t cap, size_t *blen,
                               const char *path, const char *rawval, int as_string) {
    char objkey[256];
    char subkey[256];
    const char *dot = strchr(path, '.');
    if (!dot) return 0;
    size_t ol = (size_t)(dot - path);
    if (ol >= sizeof(objkey)) return 0;
    memcpy(objkey, path, ol);
    objkey[ol] = 0;
    const char *rest = dot + 1;
    if (strcmp(rest, "*") == 0) {
        copy_trunc(subkey, sizeof(subkey), "*");
    } else {
        const char *dot2 = strchr(rest, '.');
        if (dot2) {
            size_t sl = (size_t)(dot2 - rest);
            if (sl >= sizeof(subkey)) return 0;
            memcpy(subkey, rest, sl);
            subkey[sl] = 0;
        } else {
            copy_trunc(subkey, sizeof(subkey), rest);
        }
    }

    char pat[600];
    snprintf(pat, sizeof(pat), "\"%s\"", objkey);
    char *p = strstr(body, pat);
    if (!p) return 0;
    p += strlen(pat);
    p = skip_ws(p);
    if (*p != ':') return 0;
    p++;
    p = skip_ws(p);
    if (*p != '{') return 0;

    char *obj_end = json_value_end(p);
    if (!obj_end) return 0;

    int patched = 0;
    char *cur = p + 1;
    while (cur < obj_end) {
        cur = skip_ws(cur);
        if (*cur == '}' || *cur == 0) break;
        if (*cur != '"') break;
        char *ks = cur + 1;
        char *ke = ks;
        while (*ke && *ke != '"') {
            if (*ke == '\\' && ke[1]) ke++;
            ke++;
        }
        if (*ke != '"') break;
        char *val = ke + 1;
        val = skip_ws(val);
        if (*val != ':') break;
        val++;
        val = skip_ws(val);
        char *ve = json_value_end(val);
        if (!ve) break;

        size_t keylen = (size_t)(ke - ks);
        int match = 0;
        if (subkey[0] == '*' && subkey[1] == 0) match = 1;
        else if (strlen(subkey) == keylen && strncmp(ks, subkey, keylen) == 0) match = 1;

        if (match) {
            size_t oldlen = (size_t)(ve - val);
            char newv[1200];
            int nl;
            if (as_string) nl = snprintf(newv, sizeof(newv), "\"%s\"", rawval);
            else nl = snprintf(newv, sizeof(newv), "%s", rawval);
            if (nl <= 0) break;
            size_t nlu = (size_t)nl;
            if (nlu > oldlen) {
                size_t grow = nlu - oldlen;
                if (*blen + grow + 1 > cap) return patched;
                memmove(ve + grow, ve, (*blen) - (size_t)(ve - body) + 1);
                memcpy(val, newv, nlu);
                *blen += grow;
                obj_end += grow;
                ve += grow;
            } else if (nlu < oldlen) {
                size_t shr = oldlen - nlu;
                memmove(val + nlu, ve, (*blen) - (size_t)(ve - body) + 1);
                *blen -= shr;
                obj_end -= shr;
                ve -= shr;
                memcpy(val, newv, nlu);
            } else {
                memcpy(val, newv, nlu);
            }
            patched = 1;
            cur = ve;
        } else {
            cur = ve;
        }
    }
    return patched;
}

static int json_escape_into(const char *in, char *out, size_t outsz) {
    size_t o = 0;
    while (*in) {
        unsigned char c = (unsigned char)*in;
        if (c == '"' || c == '\\') {
            if (o + 2 >= outsz) return -1;
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c == '\n') {
            if (o + 2 >= outsz) return -1;
            out[o++] = '\\'; out[o++] = 'n';
        } else if (c == '\r') {
            if (o + 2 >= outsz) return -1;
            out[o++] = '\\'; out[o++] = 'r';
        } else if (c == '\t') {
            if (o + 2 >= outsz) return -1;
            out[o++] = '\\'; out[o++] = 't';
        } else {
            if (o + 1 >= outsz) return -1;
            out[o++] = (char)c;
        }
        in++;
    }
    out[o] = 0;
    return (int)o;
}

static char *load_snippet(const char *path, size_t *out_len) {
    for (int i = 0; i < g_snip_count; i++) {
        if (strcmp(g_snips[i].path, path) == 0) {
            if (out_len) *out_len = g_snips[i].len;
            return g_snips[i].data;
        }
    }
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size <= 0 || st.st_size > 8 * 1024 * 1024) {
        logmsg("load_snippet: stat failed for '%s': %s", path, strerror(errno));
        return NULL;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        logmsg("load_snippet: fopen failed for '%s': %s", path, strerror(errno));
        return NULL;
    }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);
    if (r != (size_t)st.st_size) { free(buf); return NULL; }
    buf[r] = 0;
    if (g_snip_count >= MAX_SNIPPETS) {
        free(buf);
        return NULL;
    }
    snippet_t *s = &g_snips[g_snip_count++];
    copy_trunc(s->path, sizeof(s->path), path);
    s->data = buf;
    s->len = r;
    if (out_len) *out_len = r;
    logmsg("load_snippet: loaded '%s' (%zu bytes)", path, r);
    return buf;
}

static int load_rules(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == 0) continue;

        char *e = strchr(p, '\n');
        if (e) *e = 0;
        e = strchr(p, '\r');
        if (e) *e = 0;

        char tok[4][600];
        int ntok = 0;
        char *save = p;
        for (int i = 0; i < 4; i++) {
            char *q = save;
            while (*q == ' ' || *q == '\t') q++;
            if (!*q) break;
            if (i == 3) {
                copy_trunc(tok[3], sizeof(tok[3]), q);
                ntok = 4;
                break;
            }
            char *s = q;
            while (*q && *q != ' ' && *q != '\t') q++;
            size_t l = (size_t)(q - s);
            if (l >= sizeof(tok[0])) l = sizeof(tok[0]) - 1;
            memcpy(tok[i], s, l);
            tok[i][l] = 0;
            save = q;
            ntok = i + 1;
        }
        if (ntok < 3) continue;
        if (g_rule_count >= MAX_RULES) break;

        rule_t *r = &g_rules[g_rule_count++];
        memset(r, 0, sizeof(*r));
        copy_trunc(r->type,   sizeof(r->type),   tok[0]);
        copy_trunc(r->match,  sizeof(r->match),  tok[1]);
        copy_trunc(r->action, sizeof(r->action), tok[2]);

        if (strcmp(r->type, "html") == 0) {
            if (ntok >= 4) {
                char rawpath[600];
                copy_trunc(rawpath, sizeof(rawpath), tok[3]);
                char *kw = strstr(rawpath, "kill_ws=");
                if (kw) {
                    r->kill_ws = atoi(kw + 8);
                    char *sp = kw;
                    while (sp > rawpath && (sp[-1] == ' ' || sp[-1] == '\t')) sp--;
                    *sp = 0;
                }
                while (rawpath[0] && (rawpath[strlen(rawpath)-1] == ' ' || rawpath[strlen(rawpath)-1] == '\t'))
                    rawpath[strlen(rawpath)-1] = 0;
                copy_trunc(r->path, sizeof(r->path), rawpath);
            }
            logmsg("rule html: match='%s' path='%s' kill_ws=%d",
                   r->match, r->path, r->kill_ws);
            continue;
        }

        if (strcmp(r->type, "short") == 0) {
            if (ntok >= 4) copy_trunc(r->value, sizeof(r->value), tok[3]);
            logmsg("rule short: match='%s' value='%s'", r->match, r->value);
            continue;
        }

        if (ntok >= 4) {
            char *eq = strchr(tok[3], '=');
            if (eq) {
                size_t pl = (size_t)(eq - tok[3]);
                if (pl >= sizeof(r->path)) pl = sizeof(r->path) - 1;
                memcpy(r->path, tok[3], pl);
                r->path[pl] = 0;
                copy_trunc(r->value, sizeof(r->value), eq + 1);
            } else {
                copy_trunc(r->path, sizeof(r->path), tok[3]);
            }
        }
        logmsg("rule %s: match='%s' path='%s' value='%s'",
               r->type, r->match, r->path, r->value);
    }
    fclose(f);
    return 0;
}

static int get_orig_dst(int fd, struct sockaddr_in *out) {
    socklen_t l = sizeof(*out);
    return getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, out, &l);
}

static rule_t *find_rule_url(const char *url) {
    for (int i = 0; i < g_rule_count; i++) {
        const char *m = g_rules[i].match;
        if (!m[0]) continue;
        if (strcmp(g_rules[i].type, "short") == 0) {
            if (strncmp(url, m, strlen(m)) == 0) return &g_rules[i];
        } else if (strcmp(g_rules[i].type, "json") == 0 ||
                   strcmp(g_rules[i].type, "jsonp") == 0) {
            if (strstr(url, m)) return &g_rules[i];
        }
    }
    return NULL;
}

static rule_t *find_rule_html(const char *body) {
    for (int i = 0; i < g_rule_count; i++) {
        if (strcmp(g_rules[i].type, "html") != 0) continue;
        if (!g_rules[i].match[0]) continue;
        if (strstr(body, g_rules[i].match)) {
            logmsg("find_rule_html: matched '%s'", g_rules[i].match);
            return &g_rules[i];
        }
    }
    logmsg("find_rule_html: no match");
    return NULL;
}

static int html_inject(char *body, size_t cap, size_t *blen, const rule_t *r) {
    logmsg("html_inject: path='%s' kill_ws=%d blen=%zu cap=%zu",
           r->path, r->kill_ws, *blen, cap);
    int modified = 0;

    if (r->kill_ws) {
        char shim[1024];
        int sl = snprintf(shim, sizeof(shim),
            "<script>(function(){var O=window.WebSocket;if(!O)return;"
            "var U=\"ws://%s:8765/\";"
            "function W(u,p){"
            "if(typeof u==='string'&&u.indexOf('%s:8765')>=0)return new O(u,p);"
            "try{return new O(U,p);}catch(e){return new O(u,p);}}"
            "W.prototype=O.prototype;W.CONNECTING=O.CONNECTING;W.OPEN=O.OPEN;"
            "W.CLOSING=O.CLOSING;W.CLOSED=O.CLOSED;"
            "window.WebSocket=W;})();</script>", g_my_ip, g_my_ip);
        if (sl > 0) {
            size_t slu = (size_t)sl;
            char *head = strstr(body, "<head>");
            if (!head) head = strstr(body, "<HEAD>");
            if (head) {
                char *ins = head + 6;
                size_t off = (size_t)(ins - body);
                if (*blen + slu + 1 < cap) {
                    memmove(ins + slu, ins, (*blen) - off + 1);
                    memcpy(ins, shim, slu);
                    *blen += slu;
                    modified = 1;
                    logmsg("html_inject: shim inserted at head");
                } else {
                    logmsg("html_inject: no space for shim");
                }
            } else {
                logmsg("html_inject: no <head>");
            }
        }
    }

    size_t snip_len = 0;
    char *snip = NULL;
    if (r->path[0]) {
        snip = load_snippet(r->path, &snip_len);
    }
    if (snip && snip_len > 0) {
        char *pb = strstr(body, "</body>");
        if (!pb) pb = strstr(body, "</BODY>");
        if (pb) {
            size_t off = (size_t)(pb - body);
            if (*blen + snip_len + 1 < cap) {
                memmove(pb + snip_len, pb, (*blen) - off + 1);
                memcpy(pb, snip, snip_len);
                *blen += snip_len;
                modified = 1;
                logmsg("html_inject: snippet inserted before </body>");
            } else {
                logmsg("html_inject: no space for snippet");
            }
        } else {
            logmsg("html_inject: no </body>");
        }
    } else {
        logmsg("html_inject: snippet not loaded (path='%s')", r->path);
    }

    return modified;
}

static void handle_request(int cfd) {
    struct sockaddr_in orig;
    if (get_orig_dst(cfd, &orig) < 0) {
        logmsg("SO_ORIGINAL_DST failed: %s", strerror(errno));
        return;
    }
    if (orig.sin_port == 0) orig.sin_port = htons(80);

    char *req = malloc(BUF_REQ);
    if (!req) return;

    ssize_t hr = read_until_headers(cfd, req, BUF_REQ);
    if (hr <= 0) { free(req); return; }

    size_t reqlen = (size_t)hr;

    long content_len = 0;
    char *clp = hdr_find(req, "Content-Length", NULL);
    if (clp) content_len = atol(clp);

    if (content_len > 0) {
        if (reqlen + (size_t)content_len + 1 > BUF_REQ) { free(req); return; }
        if (read_exact(cfd, req + reqlen, (size_t)content_len) != 0) { free(req); return; }
        reqlen += (size_t)content_len;
        req[reqlen] = 0;
    }

    char method[16] = {0}, url[2048] = {0}, ver[16] = {0};
    sscanf(req, "%15s %2047s %15s", method, url, ver);
    if (!url[0]) { free(req); return; }

    logmsg("REQ %s %s", method, url);

    for (int i = 0; i < g_rule_count; i++) {
        if (strcmp(g_rules[i].type, "short") != 0) continue;
        if (strncmp(url, g_rules[i].match, strlen(g_rules[i].match)) != 0) continue;

        char val[1024];
        substitute(val, sizeof(val), g_rules[i].value[0] ? g_rules[i].value : "false");

        char resp[2048];
        int rl = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            "Content-Length: %zu\r\n"
            "Cache-Control: no-store, no-cache, must-revalidate\r\n"
            "Pragma: no-cache\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s", strlen(val), val);
        if (rl > 0) {
            ssize_t wres = write_full(cfd, resp, (size_t)rl);
            (void)wres;
        }
        logmsg("short %s -> %s", url, val);
        free(req);
        return;
    }

    hdr_remove(req, &reqlen, "Accept-Encoding");
    hdr_force_close(req, BUF_REQ, &reqlen);

    const char *hs = url;
    if (strncmp(url, "http://", 7) == 0) hs = url + 7;

    if (hs[0] == '/') {
        logmsg("relative URL, keeping Host header");
    } else {
        const char *slash = strchr(hs, '/');
        if (slash) {
            char hostbuf[512];
            size_t hl = (size_t)(slash - hs);
            if (hl < sizeof(hostbuf)) {
                memcpy(hostbuf, hs, hl);
                hostbuf[hl] = 0;
                hdr_set(req, BUF_REQ, &reqlen, "Host", hostbuf);
            }
            char newline[3072];
            int nl = snprintf(newline, sizeof(newline), "%s %s %s\r\n",
                              method, slash, ver[0] ? ver : "HTTP/1.1");
            if (nl > 0) {
                char *first_end = strstr(req, "\r\n");
                if (first_end) {
                    size_t old_first = (size_t)(first_end - req) + 2;
                    size_t diff = (size_t)nl;
                    if (diff <= old_first) {
                        memmove(req + diff, req + old_first, reqlen - old_first + 1);
                        memcpy(req, newline, diff);
                        reqlen -= old_first - diff;
                    }
                }
            }
        } else {
            hdr_set(req, BUF_REQ, &reqlen, "Host", hs);
        }
    }

    int ufd = socket(AF_INET, SOCK_STREAM, 0);
    if (ufd < 0) { free(req); return; }

    struct timeval tv = { 10, 0 };
    setsockopt(ufd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(ufd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(ufd, (struct sockaddr *)&orig, sizeof(orig)) < 0) {
        logmsg("connect to %s:%d failed: %s",
               inet_ntoa(orig.sin_addr), ntohs(orig.sin_port), strerror(errno));
        const char *e = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        ssize_t wres = write_full(cfd, e, strlen(e));
        (void)wres;
        close(ufd);
        free(req);
        return;
    }

    if (write_full(ufd, req, reqlen) < 0) {
        close(ufd);
        free(req);
        return;
    }
    free(req);

    char *resp = malloc(BUF_RESP);
    if (!resp) { close(ufd); return; }

    size_t rtotal = 0;
    ssize_t rh = read_until_headers(ufd, resp, BUF_RESP);
    if (rh <= 0) {
        close(ufd);
        free(resp);
        return;
    }
    rtotal = (size_t)rh;

    long rcl = 0;
    char *rclp = hdr_find(resp, "Content-Length", NULL);
    if (rclp) rcl = atol(rclp);

    char *rte = hdr_find(resp, "Transfer-Encoding", NULL);
    int chunked = (rte && strncasecmp(rte, "chunked", 7) == 0);

    if (chunked) {
        while (rtotal < BUF_RESP - 1) {
            ssize_t r = recv(ufd, resp + rtotal, BUF_RESP - 1 - rtotal, 0);
            if (r <= 0) break;
            rtotal += (size_t)r;
            resp[rtotal] = 0;
            size_t look = (r > 64) ? 64 : (size_t)r;
            if (strstr(resp + rtotal - look, "0\r\n\r\n")) break;
        }
    } else if (rcl > 0) {
        size_t need = rtotal + (size_t)rcl;
        if (need < BUF_RESP) {
            while (rtotal < need) {
                ssize_t r = recv(ufd, resp + rtotal, need - rtotal, 0);
                if (r <= 0) break;
                rtotal += (size_t)r;
            }
        }
    } else {
        while (rtotal < BUF_RESP - 1) {
            ssize_t r = recv(ufd, resp + rtotal, BUF_RESP - 1 - rtotal, 0);
            if (r <= 0) break;
            rtotal += (size_t)r;
        }
    }
    resp[rtotal] = 0;
    close(ufd);

    char *hdr_end = strstr(resp, "\r\n\r\n");
    if (!hdr_end) {
        if (rtotal) {
            ssize_t wres = write_full(cfd, resp, rtotal);
            (void)wres;
        }
        free(resp);
        return;
    }
    size_t hdrlen = (size_t)(hdr_end - resp) + 4;
    char *body = resp + hdrlen;
    size_t bodylen = rtotal > hdrlen ? rtotal - hdrlen : 0;

    int is_html = 0;
    char *ctp = hdr_find(resp, "Content-Type", NULL);
    if (ctp && (strncasecmp(ctp, "text/html", 9) == 0 ||
                strncasecmp(ctp, "application/xhtml", 16) == 0)) is_html = 1;

    char *codep = hdr_find(resp, "Content-Encoding", NULL);
    int encoded = codep != NULL;

    logmsg("RESP ct=%s is_html=%d enc=%d bodylen=%zu rtotal=%zu",
           ctp ? ctp : "?", is_html, encoded, bodylen, rtotal);

    int patched = 0;

    if (!encoded) {
        rule_t *url_rule = find_rule_url(url);
        if (url_rule && (strcmp(url_rule->type, "json") == 0 ||
                         strcmp(url_rule->type, "jsonp") == 0)) {
            for (int i = 0; i < g_rule_count; i++) {
                rule_t *r = &g_rules[i];
                if (strcmp(r->type, url_rule->type) != 0) continue;
                if (!strstr(url, r->match)) continue;
                if (!r->path[0]) continue;

                char rawval[600];
                substitute(rawval, sizeof(rawval), r->value);

                char *json_start = body;
                char *json_end = body + bodylen;

                if (strcmp(r->type, "jsonp") == 0) {
                    char *lp = memchr(body, '(', bodylen);
                    char *rp = NULL;
                    if (lp) {
                        for (size_t k = bodylen; k > 0; k--) {
                            if (body[k - 1] == ')') { rp = body + k - 1; break; }
                        }
                    }
                    if (lp && rp && rp > lp) {
                        json_start = lp + 1;
                        json_end = rp;
                    }
                }

                size_t jlen = (size_t)(json_end - json_start);
                if (jlen == 0) continue;

                char *tmpj = malloc(jlen + 8192);
                if (!tmpj) continue;
                memcpy(tmpj, json_start, jlen);
                tmpj[jlen] = 0;
                size_t tmplen = jlen;

                int did = 0;
                if (strchr(r->path, '*')) {
                    did = json_patch_wildcard(tmpj, jlen + 8191, &tmplen, r->path, rawval,
                                              strcmp(r->type, "json") == 0);
                } else {
                    const char *lastdot = strrchr(r->path, '.');
                    const char *key = lastdot ? lastdot + 1 : r->path;
                    char val_quoted[1200];
                    if (strcmp(r->type, "json") == 0) {
                        char esc[600];
                        if (json_escape_into(rawval, esc, sizeof(esc)) < 0) esc[0] = 0;
                        snprintf(val_quoted, sizeof(val_quoted), "\"%s\"", esc);
                    } else {
                        snprintf(val_quoted, sizeof(val_quoted), "%s", rawval);
                    }
                    did = json_patch_key(tmpj, jlen + 8191, &tmplen, key, val_quoted);
                }

                if (did) {
                    size_t new_jlen = tmplen;
                    size_t old_jlen = jlen;
                    long diff = (long)new_jlen - (long)old_jlen;
                    if (diff > 0) {
                        if (bodylen + (size_t)diff + 1 > BUF_RESP - hdrlen) {
                            free(tmpj);
                            continue;
                        }
                        memmove(json_end + diff, json_end,
                                bodylen - (size_t)(json_end - body) + 1);
                        memcpy(json_start, tmpj, new_jlen);
                        bodylen += (size_t)diff;
                        rtotal += (size_t)diff;
                    } else if (diff < 0) {
                        memcpy(json_start, tmpj, new_jlen);
                        memmove(json_start + new_jlen, json_end,
                                bodylen - (size_t)(json_end - body) + 1);
                        bodylen -= (size_t)(-diff);
                        rtotal -= (size_t)(-diff);
                    } else {
                        memcpy(json_start, tmpj, new_jlen);
                    }
                    resp[rtotal] = 0;
                    body = resp + hdrlen;
                    patched = 1;
                    logmsg("json patched: %s", r->path);
                }
                free(tmpj);
            }
        }

        if (is_html) {
            rule_t *hr2 = find_rule_html(body);
            if (hr2) {
                if (html_inject(body, BUF_RESP - hdrlen, &bodylen, hr2)) {
                    rtotal = hdrlen + bodylen;
                    resp[rtotal] = 0;
                    patched = 1;
                }
            }
        }
    }

    if (patched) {
        char num[32];
        snprintf(num, sizeof(num), "%zu", bodylen);
        hdr_set(resp, BUF_RESP, &rtotal, "Content-Length", num);
        hdr_remove(resp, &rtotal, "Content-Encoding");
        hdr_remove(resp, &rtotal, "Transfer-Encoding");
        hdr_remove(resp, &rtotal, "ETag");
        hdr_remove(resp, &rtotal, "Last-Modified");
        hdr_remove(resp, &rtotal, "Expires");
        hdr_remove(resp, &rtotal, "Cache-Control");
        hdr_set(resp, BUF_RESP, &rtotal, "Cache-Control", "no-store, no-cache, must-revalidate");
        hdr_set(resp, BUF_RESP, &rtotal, "Pragma", "no-cache");
        hdr_force_close(resp, BUF_RESP, &rtotal);
        logmsg("patched: new rtotal=%zu bodylen=%zu", rtotal, bodylen);
    }

    ssize_t wres = write_full(cfd, resp, rtotal);
    (void)wres;
    free(resp);
}

static void *thread_worker(void *arg) {
    int cfd = (int)(intptr_t)arg;
    handle_request(cfd);
    shutdown(cfd, SHUT_RDWR);
    close(cfd);
    return NULL;
}

static void on_signal(int sig) {
    (void)sig;
    static const char msg[] = "[cproxy] shutting down\n";
    ssize_t r = write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)r;
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s <port> <my_ip> <rules.conf> <inject.js>\n", argv[0]);
        return 1;
    }
    g_port = atoi(argv[1]);
    if (g_port <= 0 || g_port > 65535) {
        fprintf(stderr, "invalid port\n");
        return 1;
    }
    copy_trunc(g_my_ip, sizeof(g_my_ip), argv[2]);

    if (load_rules(argv[3]) != 0) {
        fprintf(stderr, "cannot load rules: %s\n", argv[3]);
        return 1;
    }

    size_t deflen = 0;
    char *defsnip = load_snippet(argv[4], &deflen);

    int html_without_path = 0;
    for (int i = 0; i < g_rule_count; i++) {
        if (strcmp(g_rules[i].type, "html") == 0 && g_rules[i].path[0] == 0 && defsnip) {
            copy_trunc(g_rules[i].path, sizeof(g_rules[i].path), argv[4]);
            html_without_path++;
        }
    }

    signal(SIGPIPE, SIG_IGN);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = INADDR_ANY;
    a.sin_port = htons((uint16_t)g_port);

    if (bind(srv, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); return 1; }
    if (listen(srv, 128) < 0) { perror("listen"); return 1; }

    logmsg("started port=%d my_ip=%s rules=%d default_snippet=%s (%zu bytes, %d html default)",
           g_port, g_my_ip, g_rule_count, argv[4], deflen, html_without_path);

    while (1) {
        struct sockaddr_in c;
        socklen_t cl = sizeof(c);
        int cfd = accept(srv, (struct sockaddr *)&c, &cl);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            continue;
        }
        int nd = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nd, sizeof(nd));
        pthread_t th;
        if (pthread_create(&th, NULL, thread_worker, (void *)(intptr_t)cfd) == 0) {
            pthread_detach(th);
        } else {
            close(cfd);
        }
    }
    return 0;
}
