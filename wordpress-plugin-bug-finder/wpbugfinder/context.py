"""Entry-point / attacker-context analysis.

Maps WordPress hook registrations to the callback that handles them and
derives the minimum privilege level an attacker needs to reach the callback
("Unauthenticated", "Subscriber+", "Contributor+", "Administrator+"),
mirroring how Wordfence titles vulnerabilities.
"""

import re

from . import php as phpmod
from .criteria import (UNAUTHENTICATED, SUBSCRIBER, ADMIN, context_for_privilege)

_CALLBACK = (
    r"(?P<cb>'[^']+'|\"[^\"]+\"|array\s*\(\s*[^)]+\)|\[[^\]]+\]|"
    r"[A-Za-z_][\w\\\\]*::\s*\$?\w+|\$this\s*->\s*\w+|"
    r"[A-Za-z_]\w*(?:\s+as\s+[A-Za-z_]\w+)?(?:\s*\?\?\s*'[^']*')?)")

ADD_ACTION = re.compile(
    r"add_action\s*\(\s*['\"]([\w\-.:]+)['\"]\s*,\s*" + _CALLBACK, re.S)

ADD_SHORTCODE = re.compile(
    r"add_shortcode\s*\(\s*['\"]([\w\-.]+)['\"]\s*,\s*" + _CALLBACK, re.S)

ADMIN_MENU_PAGES = re.compile(
    r"add_(?:menu|options|submenu|management|theme|plugins|users|dashboard|"
    r"posts|media|links)_page\s*\(")

REGISTER_REST = re.compile(r"register_rest_route\s*\(")

UNAUTH_TAGS = ("wp_ajax_nopriv_", "admin_post_nopriv_", "_nopriv_")
PRIV_TAGS = ("wp_ajax_", "admin_post_")

FRONTEND_HOOKS = {
    "init", "wp_loaded", "plugins_loaded", "wp_head", "wp_footer", "wp_enqueue_scripts",
    "template_redirect", "wp", "parse_request", "parse_query", "the_content",
    "wp_print_scripts", "rest_api_init", "wp_title", "admin_bar_menu",
    "wp_ajax_dummy", "pre_get_posts", "the_posts", "save_post", "publish_post",
}

ADMIN_HOOKS = {
    "admin_init", "admin_menu", "admin_notices", "admin_footer",
    "load-plugins.php", "admin_enqueue_scripts", "personal_options_update",
    "edit_user_profile_update", "admin_action_",  # prefix
}

STATE_WRITES = re.compile(
    r"\b(?P<write>update_option|add_option|delete_option|update_site_option|"
    r"update_network_option|wp_update_post|wp_insert_post|wp_trash_post|"
    r"wp_delete_post|update_post_meta|delete_post_meta|add_post_meta|"
    r"update_user_meta|delete_user_meta|update_user_option|wp_update_user|"
    r"wp_insert_user|delete_user|delete_user_meta|wpmu_delete_user|"
    r"delete_transient|set_transient|delete_site_transient|"
    r"set_site_transient|unlink|fwrite|file_put_contents|rename|touch|"
    r"chmod|symlink|switch_to_blog|restore_current_blog|wp_remote_post|"
    r"wp_remote_request|wp_mail|do_shortcode|switch_theme|"
    r"deactivate_plugins)\b"
    r"|\$wpdb\s*->\s*(?:insert|update|delete|query)\b"
    r"|->\s*(?:save|delete|update|get_results|get_var|get_row|get_col)\s*\(")


def _parse_callback(cb: str):
    """Return (class_hint, method_or_function_name | None)."""
    cb = cb.strip()
    arr = re.match(
        r"(?:array|\[)\s*\(?\s*(\$this|self|static|\$[A-Za-z_]\w*|[A-Za-z_][\w\\\\]*)"
        r"\s*(?:class)?\s*,\s*['\"]?([\w]+)", cb)
    if arr:
        return arr.group(1), arr.group(2)
    staticm = re.match(r"['\"]?([A-Za-z_][\w\\\\]*)::([\w]+)['\"]?", cb)
    if staticm:
        return staticm.group(1), staticm.group(2)
    strc = re.match(r"['\"]([A-Za-z_][\w]*)['\"]", cb)
    if strc and (".php" not in strc.group(1)):
        return None, strc.group(1)
    return None, None


class Endpoint:
    __slots__ = ("hook", "callback", "privilege", "line", "kind", "note",
                 "func_pos")

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)

    def attacker_ctx(self):
        return context_for_privilege(self.privilege)


def endpoints(masked: str) -> list:
    """Everything an attacker can potentially reach, with the privilege the
    attacker needs to reach it."""
    eps = []
    funcs = list(phpmod.functions(masked))

    def pos_of(func_name, class_hint):
        for (name, bpos, bend, fpos) in funcs:
            if name == func_name:
                if class_hint in (None, "$this", "self", "static"):
                    return bpos
        for (name, bpos, bend, fpos) in funcs:
            if name == func_name:
                return bpos
        return None

    for m in ADD_ACTION.finditer(masked):
        tag, cb = m.group(1), m.group("cb")
        cls, fn = _parse_callback(cb)
        if fn is None:
            continue
        line = phpmod.line_of(masked, m.start())
        # strip 'admin_action_' style prefixes
        if tag.startswith("wp_ajax_nopriv_") or tag.startswith("admin_post_nopriv_"):
            priv, kind = "unauthenticated", ("ajax" if tag.startswith("wp_ajax") else "form")
        elif tag.startswith("wp_ajax_") or tag.startswith("admin_post_"):
            priv, kind = "subscriber", ("ajax" if tag.startswith("wp_ajax") else "form")
        elif any(tag.startswith(a) for a in ("admin_action_", "load-")):
            priv, kind = "subscriber", "admin"
        elif tag in ADMIN_HOOKS:
            priv, kind = "subscriber", "admin"
        elif tag in FRONTEND_HOOKS:
            priv, kind = "unauthenticated", "frontend"
        else:
            continue
        bpos = pos_of(fn, cls)
        eps.append(Endpoint(hook=tag, callback=(cls, fn), privilege=priv,
                            line=line, kind=kind, note=None, func_pos=bpos))

    for m in ADD_SHORTCODE.finditer(masked):
        cls, fn = _parse_callback(m.group("cb"))
        if fn is None:
            continue
        bpos = pos_of(fn, cls)
        eps.append(Endpoint(hook=f"shortcode:{m.group(1)}", callback=(cls, fn),
                            privilege="unauthenticated", kind="shortcode",
                            line=phpmod.line_of(masked, m.start()), note=None,
                            func_pos=bpos))

    # REST routes: resolve the 'callback' argument to a function whenever the
    # call is written inline (register_rest_route('ns', '/path', [ 'callback'
    # => fn ])).  Unauthenticated unless a permission_callback is present.
    for m in REGISTER_REST.finditer(masked):
        open_pos = masked.index("(", m.start())
        close_pos = phpmod.match_paren(masked, open_pos)
        if close_pos == -1:
            continue
        call = masked[open_pos:close_pos]
        has_pc = "permission_callback" in call
        cls, fn = (None, None)
        cbm = re.search(
            r"['\"]callback['\"]\s*=>\s*(" + _CALLBACK + r")", call, re.S)
        if cbm:
            cls, fn = _parse_callback(cbm.group(1))
            bpos = pos_of(fn, cls) if fn is not None else None
        else:
            bpos = None
        ep = Endpoint(hook="rest_route", callback=(cls, fn) if fn else (),
                      privilege=None, kind="rest",
                      line=phpmod.line_of(masked, m.start()),
                      note="no permission_callback" if not has_pc
                      else "permission_callback present", func_pos=bpos)
        if not has_pc:
            ep.privilege = "unauthenticated"
        else:
            ep.privilege = "subscriber"
        eps.append(ep)

    return [e for e in eps if e.privilege]


def function_bodies(masked: str):
    """[(name, body_text, body_offset)] for each function."""
    for (name, bpos, bend, fpos) in phpmod.functions(masked):
        yield name, masked[bpos + 1:bend], bpos


HAS_NONCE_CHECK = re.compile(
    r"\b(check_admin_referer|check_ajax_referer|wp_verify_nonce|"
    r"wp_validate_auth_cookie|wp_rest)\b")
HAS_CAP_CHECK = re.compile(
    r"\b(current_user_can|is_user_logged_in|user_can|get_current_user_id|"
    r"is_super_admin|current_user_can_for_blog|wp_get_current_user)\b")


def body_iterates_post(body: str) -> bool:
    return "$_POST" in body or "$_REQUEST" in body or "$_GET" in body \
        or "$_FILES" in body or "php://input" in body
