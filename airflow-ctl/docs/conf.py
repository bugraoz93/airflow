# Disable Flake8 because of all the sphinx imports
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Configuration of Providers docs building."""

from __future__ import annotations

import logging
import os
import pathlib
import re
from typing import Any

from docs.utils.conf_constants import (
    AIRFLOW_CTL_DOC_STATIC_PATH,
    AIRFLOW_CTL_SRC_PATH,
    AIRFLOW_FAVICON_PATH,
    AUTOAPI_OPTIONS,
    BASIC_AUTOAPI_IGNORE_PATTERNS,
    BASIC_SPHINX_EXTENSIONS,
    REDOC_SCRIPT_URL,
    SMARTQUOTES_EXCLUDES,
    SPELLING_WORDLIST_PATH,
    SPHINX_DESIGN_STATIC_PATH,
    SPHINX_REDOC_EXTENSIONS,
    SUPPRESS_WARNINGS,
    filter_autoapi_ignore_entries,
    get_autodoc_mock_imports,
    get_configs_and_deprecations,
    get_google_intersphinx_mapping,
    get_html_context,
    get_html_sidebars,
    get_html_theme_options,
    get_intersphinx_mapping,
    get_rst_epilogue,
    get_rst_filepath_from_path,
    skip_util_classes_extension,
)
from packaging.version import Version, parse as parse_version

import airflowctl
from airflow.configuration import retrieve_configuration_description

PACKAGE_NAME = "apache-airflow-ctl"
PACKAGE_VERSION = airflowctl.__version__
SYSTEM_TESTS_DIR: pathlib.Path | None
# SYSTEM_TESTS_DIR = AIRFLOW_REPO_ROOT_PATH / "airflow-ctl" / "tests" / "system" / "core"

conf_py_path = f"/docs/{PACKAGE_NAME}/"

os.environ["AIRFLOW_PACKAGE_NAME"] = PACKAGE_NAME

# Hack to allow changing for piece of the code to behave differently while
# the docs are being built. The main objective was to alter the
# behavior of the utils.apply_default that was hiding function headers
os.environ["BUILDING_AIRFLOW_DOCS"] = "TRUE"

# General information about the project.
project = PACKAGE_NAME
# # The version info for the project you're documenting
version = PACKAGE_VERSION
# The full version, including alpha/beta/rc tags.
release = PACKAGE_VERSION

rst_epilog = get_rst_epilogue(PACKAGE_VERSION, True)

# The language for content autogenerated by Sphinx. Refer to documentation
smartquotes_excludes = SMARTQUOTES_EXCLUDES

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = BASIC_SPHINX_EXTENSIONS

# -- Options for sphinxcontrib.redoc -------------------------------------------
# See: https://sphinxcontrib-redoc.readthedocs.io/en/stable/

extensions.extend(SPHINX_REDOC_EXTENSIONS)
redoc_script_url = REDOC_SCRIPT_URL

extensions.extend(
    [
        "autoapi.extension",
        "sphinx_jinja",
        "sphinx.ext.graphviz",
        "sphinxcontrib.httpdomain",
        "extra_files_with_substitutions",
    ]
)

exclude_patterns = [
    # We only link to selected subpackages.
    "_api/airflowctl/index.rst",
    "_api/airflowctl/api/datamodels/auth_generated/index.rst",
    "_api/airflowctl/api/datamodels/generated/index.rst",
    "_api/airflowctl/api/index.rst",
    "_api/airflowctl/ctl/index.rst",
    "README.rst",
]

# Exclude top-level packages
# do not exclude these top-level modules from the doc build:
ALLOWED_TOP_LEVEL_FILES = ("exceptions.py",)


def add_airflow_core_exclude_patterns_to_sphinx(exclude_patterns: list[str]):
    """
    Add excluded files to Sphinx exclude patterns.

    Excludes all files from autoapi except the ones we want to allow.

    :param root: The root directory of the package.
    :param allowed_top_level_files: Tuple of allowed top-level files.
    :param browsable_packages: Set of browsable packages.
    :param browsable_utils: Set of browsable utils.
    :param models_included: Set of included models.
    """
    # first - excluded everything that is not allowed or browsable
    root = AIRFLOW_CTL_SRC_PATH / "airflowctl"
    for path in root.iterdir():
        if path.is_file() and path.name not in ALLOWED_TOP_LEVEL_FILES:
            exclude_patterns.append(get_rst_filepath_from_path(path, root.parent))


add_airflow_core_exclude_patterns_to_sphinx(exclude_patterns)

# Add any paths that contain templates here, relative to this directory.
templates_path = ["templates"]

# If true, keep warnings as "system message" paragraphs in the built documents.
keep_warnings = True

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = "sphinx_airflow_theme"

html_title = "Airflow Documentation"

# A shorter title for the navigation bar.  Default is the same as html_title.
html_short_title = ""

#  given, this must be the name of an image file that is the favicon of the docs
html_favicon = AIRFLOW_FAVICON_PATH.as_posix()

# Custom static files (such as style sheets) here,
html_static_path = [AIRFLOW_CTL_DOC_STATIC_PATH.as_posix(), SPHINX_DESIGN_STATIC_PATH.as_posix()]

# A list of JavaScript filenames.
html_js_files = ["gh-jira-links.js", "redirects.js"]

# Substitute in links
manual_substitutions_in_generated_html = [
    "installation/installing-from-pypi.html",
    "installation/installing-from-sources.html",
]

html_css_files = ["custom.css"]

html_sidebars = get_html_sidebars(PACKAGE_VERSION)

# If false, no index is generated.
html_use_index = True

# If true, "(C) Copyright ..." is shown in the HTML footer. Default is True.
html_show_copyright = False

# html theme options
html_theme_options: dict[str, Any] = get_html_theme_options()

# A dictionary of values to pass into the template engine's context for all pages.
html_context = get_html_context(conf_py_path)

# -- Options for sphinx_jinja ------------------------------------------
# See: https://github.com/tardyp/sphinx-jinja
airflowctl_version: Version = parse_version(
    re.search(  # type: ignore[union-attr,arg-type]
        r"__version__ = \"([0-9.]*)(\.dev[0-9]*)?\"",
        (AIRFLOW_CTL_SRC_PATH / "airflowctl" / "__init__.py").read_text(),
    ).groups(0)[0]
)


config_descriptions = retrieve_configuration_description(include_providers=False)
configs, deprecated_options = get_configs_and_deprecations(airflowctl_version, config_descriptions)

jinja_contexts = {
    "config_ctx": {"configs": configs, "deprecated_options": deprecated_options},
    "quick_start_ctx": {"doc_root_url": f"https://airflow.apache.org/docs/apache-airflow/{PACKAGE_VERSION}/"},
    "official_download_page": {
        "base_url": f"https://downloads.apache.org/airflow/{PACKAGE_VERSION}",
        "closer_lua_url": f"https://www.apache.org/dyn/closer.lua/airflow/{PACKAGE_VERSION}",
        "airflow_version": PACKAGE_VERSION,
    },
}

# -- Options for sphinx.ext.autodoc --------------------------------------------
# See: https://www.sphinx-doc.org/en/master/usage/extensions/autodoc.html

# This value contains a list of modules to be mocked up. This is useful when some external dependencies
# are not met at build time and break the building process.
autodoc_mock_imports = get_autodoc_mock_imports()
# The default options for autodoc directives. They are applied to all autodoc directives automatically.
autodoc_default_options = {"show-inheritance": True, "members": True}

autodoc_typehints = "description"
autodoc_typehints_description_target = "documented"
autodoc_typehints_format = "short"


# -- Options for sphinx.ext.intersphinx ----------------------------------------
# See: https://www.sphinx-doc.org/en/master/usage/extensions/intersphinx.html

# This config value contains names of other projects that should
# be linked to in this documentation.
# Inventories are only downloaded once by exts/docs_build/fetch_inventories.py.
intersphinx_mapping = get_intersphinx_mapping()
intersphinx_mapping.update(get_google_intersphinx_mapping())

# -- Options for sphinx.ext.viewcode -------------------------------------------
# See: https://www.sphinx-doc.org/es/master/usage/extensions/viewcode.html

# If this is True, viewcode extension will emit viewcode-follow-imported event to resolve the name of
# the module by other extensions. The default is True.
viewcode_follow_imported_members = True

# -- Options for sphinx-autoapi ------------------------------------------------
# See: https://sphinx-autoapi.readthedocs.io/en/latest/config.html

# your API documentation from.
autoapi_dirs = [AIRFLOW_CTL_SRC_PATH.as_posix()]

# A directory that has user-defined templates to override our default templates.
autoapi_template_dir = "autoapi_templates"

# A list of patterns to ignore when finding files
autoapi_ignore = BASIC_AUTOAPI_IGNORE_PATTERNS

# filter logging
autoapi_log = logging.getLogger("sphinx.autoapi.mappers.base")
autoapi_log.addFilter(filter_autoapi_ignore_entries)

# Keep the AutoAPI generated files on the filesystem after the run.
# Useful for debugging.
autoapi_keep_files = True

# Relative path to output the AutoAPI files into. This can also be used to place the generated documentation
# anywhere in your documentation hierarchy.
autoapi_root = "_api"

# Whether to insert the generated documentation into the TOC tree. If this is False, the default AutoAPI
# index page is not generated and you will need to include the generated documentation in a
# TOC tree entry yourself.
autoapi_add_toctree_entry = False

# By default autoapi will include private members -- we don't want that!
autoapi_options = AUTOAPI_OPTIONS

suppress_warnings = SUPPRESS_WARNINGS

# -- Options for ext.exampleinclude --------------------------------------------
exampleinclude_sourceroot = os.path.abspath("..")

# -- Options for ext.redirects -------------------------------------------------
redirects_file = "redirects.txt"

# -- Options for sphinxcontrib-spelling ----------------------------------------
spelling_word_list_filename = [SPELLING_WORDLIST_PATH.as_posix()]
spelling_exclude_patterns = ["project.rst", "changelog.rst"]

spelling_ignore_contributor_names = False
spelling_ignore_importable_modules = True

graphviz_output_format = "svg"


def setup(sphinx):
    sphinx.connect("autoapi-skip-member", skip_util_classes_extension)
