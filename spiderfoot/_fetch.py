import random
import time
import urllib.parse

import requests

import spiderfoot.helpers as SpiderFootHelpers
from sflib import SpiderFoot

sf: SpiderFoot


def fetchUrl(
    url: str,
    cookies: str | None = None,
    timeout: int = 30,
    useragent: str = "SpiderFoot",
    headers: dict | None = None,
    noLog: bool = False,
    postData: str | None = None,
    disableContentEncoding: bool = False,
    sizeLimit: int | None = None,
    headOnly: bool = False,
    verify: bool = True
) -> dict | None:
    """Fetch a URL and return the HTTP response as a dictionary.

    Args:
        url (str): URL to fetch
        cookies (str | None): cookies
        timeout (int): timeout
        useragent (str): user agent header
        headers (dict | None): headers
        noLog (bool): do not log request
        postData (str | None): HTTP POST data
        disableContentEncoding (bool): do not UTF-8 encode response body
        sizeLimit (int | None): size threshold
        headOnly (bool): use HTTP HEAD method
        verify (bool): use HTTPS SSL/TLS verification

    Returns:
        dict | None: HTTP response
    """
    if not url:
        return None

    result = {
        'code': None,
        'status': None,
        'content': None,
        'headers': None,
        'realurl': url
    }

    url = url.strip()

    try:
        parsed_url = urllib.parse.urlparse(url)
    except Exception:
        sf.debug(f"Could not parse URL: {url}")
        return None

    if parsed_url.scheme != 'http' and parsed_url.scheme != 'https':
        sf.debug(f"Invalid URL scheme for URL: {url}")
        return None

    request_log = []

    proxies = dict()
    if sf.useProxyForUrl(url):
        proxies = {
            'http': sf.socksProxy,
            'https': sf.socksProxy,
        }

    header = dict()
    btime = time.time()

    if isinstance(useragent, list):
        header['User-Agent'] = random.SystemRandom().choice(useragent)
    else:
        header['User-Agent'] = useragent

    # Add custom headers
    if isinstance(headers, dict):
        for k in list(headers.keys()):
            header[k] = str(headers[k])

    request_log.append(f"proxy={sf.socksProxy}")
    request_log.append(f"user-agent={header['User-Agent']}")
    request_log.append(f"timeout={timeout}")
    request_log.append(f"cookies={cookies}")

    if sizeLimit or headOnly:
        if noLog:
            sf.debug(f"Fetching (HEAD): {sf.removeUrlCreds(url)} ({', '.join(request_log)})")
        else:
            sf.info(f"Fetching (HEAD): {sf.removeUrlCreds(url)} ({', '.join(request_log)})")

        try:
            hdr = sf.getSession().head(
                url,
                headers=header,
                proxies=proxies,
                verify=verify,
                timeout=timeout
            )
        except Exception as e:
            if noLog:
                sf.debug(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {url}", exc_info=True)
            else:
                sf.error(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {url}", exc_info=True)

            return result

        size = int(hdr.headers.get('content-length', 0))
        newloc = hdr.headers.get('location', url).strip()

        # Relative re-direct
        if newloc.startswith("/") or newloc.startswith("../"):
            newloc = SpiderFootHelpers.urlBaseUrl(url) + newloc
        result['realurl'] = newloc
        result['code'] = str(hdr.status_code)

        if headOnly:
            return result

        if size > sizeLimit:
            return result

        if result['realurl'] != url:
            if noLog:
                sf.debug(f"Fetching (HEAD): {sf.removeUrlCreds(result['realurl'])} ({', '.join(request_log)})")
            else:
                sf.info(f"Fetching (HEAD): {sf.removeUrlCreds(result['realurl'])} ({', '.join(request_log)})")

            try:
                hdr = sf.getSession().head(
                    result['realurl'],
                    headers=header,
                    proxies=proxies,
                    verify=verify,
                    timeout=timeout
                )
                size = int(hdr.headers.get('content-length', 0))
                result['realurl'] = hdr.headers.get('location', result['realurl'])
                result['code'] = str(hdr.status_code)

                if size > sizeLimit:
                    return result

            except Exception as e:
                if noLog:
                    sf.debug(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {result['realurl']}", exc_info=True)
                else:
                    sf.error(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {result['realurl']}", exc_info=True)

                return result

    try:
        if postData:
            if noLog:
                sf.debug(f"Fetching (POST): {sf.removeUrlCreds(url)} ({', '.join(request_log)})")
            else:
                sf.info(f"Fetching (POST): {sf.removeUrlCreds(url)} ({', '.join(request_log)})")
            res = sf.getSession().post(
                url,
                data=postData,
                headers=header,
                proxies=proxies,
                allow_redirects=True,
                cookies=cookies,
                timeout=timeout,
                verify=verify
            )
        else:
            if noLog:
                sf.debug(f"Fetching (GET): {sf.removeUrlCreds(url)} ({', '.join(request_log)})")
            else:
                sf.info(f"Fetching (GET): {sf.removeUrlCreds(url)} ({', '.join(request_log)})")
            res = sf.getSession().get(
                url,
                headers=header,
                proxies=proxies,
                allow_redirects=True,
                cookies=cookies,
                timeout=timeout,
                verify=verify
            )
    except requests.exceptions.RequestException as e:
        sf.error(f"Failed to connect to {url}: {e}")
        return result
    except Exception as e:
        if noLog:
            sf.debug(f"Unexpected exception ({e}) occurred fetching URL: {url}", exc_info=True)
        else:
            sf.error(f"Unexpected exception ({e}) occurred fetching URL: {url}", exc_info=True)

        return result

    try:
        result['headers'] = dict()
        result['realurl'] = res.url
        result['code'] = str(res.status_code)

        for header, value in res.headers.items():
            result['headers'][str(header).lower()] = str(value)

        # Sometimes content exceeds the size limit after decompression
        if sizeLimit and len(res.content) > sizeLimit:
            sf.debug(f"Content exceeded size limit ({sizeLimit}), so returning no data just headers")
            return result

        refresh_header = result['headers'].get('refresh')
        if refresh_header:
            try:
                newurl = refresh_header.split(";url=")[1]
            except Exception as e:
                sf.debug(f"Refresh header '{refresh_header}' found, but not parsable: {e}")
                return result

            sf.debug(f"Refresh header '{refresh_header}' found, re-directing to {sf.removeUrlCreds(newurl)}")

            return sf.fetchUrl(
                newurl,
                cookies,
                timeout,
                useragent,
                headers,
                noLog,
                postData,
                disableContentEncoding,
                sizeLimit,
                headOnly
            )

        if disableContentEncoding:
            result['content'] = res.content
        else:
            for encoding in ("utf-8", "ascii"):
                try:
                    result["content"] = res.content.decode(encoding)
                except UnicodeDecodeError:
                    pass
                else:
                    break
            else:
                result["content"] = res.content

    except Exception as e:
        sf.error(f"Unexpected exception ({e}) occurred parsing response for URL: {url}", exc_info=True)
        result['content'] = None
        result['status'] = str(e)

    atime = time.time()
    t = str(atime - btime)
    sf.info(f"Fetched {sf.removeUrlCreds(url)} ({len(result['content'] or '')} bytes in {t}s)")
    return result
