"""Tests for the error pages shown instead of the plain server defaults."""


def test_unknown_page_shows_the_site_error_page(client):
    """A page that does not exist gives 404 in the site's own style."""
    response = client.get("/no-such-page")

    assert response.status_code == 404
    assert b"That page does not exist." in response.data


def test_error_page_uses_the_site_layout(client):
    """The error page is a normal page, so it carries the top bar and stylesheet."""
    response = client.get("/no-such-page")

    assert b"Team 20 Secure Login" in response.data
    assert b"app.css" in response.data


def test_refused_page_gives_the_same_vague_wording(client):
    """A normal user sent to the admin page is refused without being told why."""
    client.post(
        "/login",
        data={
            "csrf_token": csrf_token_from(client),
            "email": "alice@example.com",
            "password": "alice-demo-pass",
        },
    )

    response = client.get("/admin")

    assert response.status_code == 403
    assert b"You do not have access to this page." in response.data
    # The page must not hint that the account is real but lacks the admin role
    assert b"admin" not in response.data.lower().replace(b"/admin", b"")


def csrf_token_from(client) -> str:
    """Read the CSRF token out of the login form."""
    page = client.get("/login").get_data(as_text=True)
    marker = 'name="csrf_token" value="'
    start = page.index(marker) + len(marker)
    return page[start:page.index('"', start)]
