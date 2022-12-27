from enum import Enum

class TableFormat(Enum):
    SIMPLE = "simple"
    """simple is the default format. It corresponds to simple_tables in 
    Pandoc Markdown extensions"""
    
    GITHUB = "github"
    """github follows the conventions of GitHub flavored Markdown"""

    JIRA = "jira"
    """jira follows the conventions of Atlassian Jira markup language"""

    PRETTY = "pretty"
    """pretty attempts to be close to the format emitted by the PrettyTables library"""

    RST = "rst"
    """rst formats data like a simple table of the reStructuredText format"""

    MEDIAWIKI = "mediawiki"
    """mediawiki format produces a table markup used in Wikipedia and on 
    other MediaWiki-based sites"""
    
    MOINMOIN = "moinmoin"
    """moinmoin format produces a table markup used in MoinMoin wikis"""

    YOUTRACK = "youtrack"
    """youtrack format produces a table markup used in Youtrack tickets"""

    HTML = "html"
    """html produces standard HTML markup as an html.escape'd str with a .repr_html 
    method so that Jupyter Lab and Notebook display the HTML and a .str property so 
    that the raw HTML remains accessible."""

    def __str__(self) -> str:
        return str(self.value)