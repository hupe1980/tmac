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

    def __str__(self) -> str:
        return str(self.value)