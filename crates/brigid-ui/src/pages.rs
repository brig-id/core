//! SSR-rendered HTML pages.

use leptos::prelude::*;
use reactive_graph::owner::Owner;
use tachys::view::RenderHtml;

/// Render the login page to an HTML string.
pub fn render_login_page() -> String {
    render_to_html(LoginPage)
}

fn render_to_html<F, V>(component: F) -> String
where
    F: FnOnce() -> V + 'static,
    V: IntoView,
{
    let owner = Owner::new();
    let html = owner.with(|| component().into_view().to_html());
    drop(owner);
    html
}

#[component]
fn LoginPage() -> impl IntoView {
    view! {
        <html lang="en">
            <head>
                <meta charset="UTF-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1.0" />
                <title>"brig·id — Sign in"</title>
            </head>
            <body>
                <main>
                    <h1>"Sign in to brig·id"</h1>
                    <form id="login-form">
                        <label for="username">"Username (format: user@server)"</label>
                        <input
                            id="username"
                            name="username"
                            type="text"
                            autocomplete="username"
                            placeholder="alice@example.com"
                            required
                        />
                        <button type="submit">"Sign in with passkey"</button>
                    </form>
                </main>
            </body>
        </html>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_page_contains_expected_elements() {
        let html = render_login_page();
        assert!(html.contains("<title>"), "missing <title>");
        assert!(html.contains("passkey"), "missing passkey button text");
        assert!(html.contains("username"), "missing username input");
    }
}
