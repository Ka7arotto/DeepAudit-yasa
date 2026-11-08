"""Server-side templates must be scanned and indexed (JSP/ASP.NET/ERB/EJS/... hold request handling)."""

import pytest

from app.core.file_types import SERVER_TEMPLATE_EXTENSIONS
from app.services.scanner import is_text_file


@pytest.mark.parametrize("name", ["WebContent/delptnt.jsp", "Views/Home/Index.cshtml",
                                  "views/profile.ejs", "templates/page.twig", "app/views/show.erb"])
def test_scanner_accepts_server_templates(name):
    assert is_text_file(name)
