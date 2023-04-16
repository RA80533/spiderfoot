"""
This type stub file was generated by pyright.
"""

import re
import itertools
import textwrap
import functools
from importlib.resources import files
from jaraco.functools import compose, method_cache
from jaraco.context import ExceptionTrap

def substitution(old, new): # -> (s: Unknown) -> Unknown:
    """
    Return a function that will perform a substitution on a string
    """
    ...

def multi_substitution(*substitutions): # -> (*args: Unknown, **kwargs: Unknown) -> Unknown:
    """
    Take a sequence of pairs specifying substitutions, and create
    a function that performs those substitutions.

    >>> multi_substitution(('foo', 'bar'), ('bar', 'baz'))('foo')
    'baz'
    """
    ...

class FoldedCase(str):
    """
    A case insensitive string class; behaves just like str
    except compares equal when the only variation is case.

    >>> s = FoldedCase('hello world')

    >>> s == 'Hello World'
    True

    >>> 'Hello World' == s
    True

    >>> s != 'Hello World'
    False

    >>> s.index('O')
    4

    >>> s.split('O')
    ['hell', ' w', 'rld']

    >>> sorted(map(FoldedCase, ['GAMMA', 'alpha', 'Beta']))
    ['alpha', 'Beta', 'GAMMA']

    Sequence membership is straightforward.

    >>> "Hello World" in [s]
    True
    >>> s in ["Hello World"]
    True

    Allows testing for set inclusion, but candidate and elements
    must both be folded.

    >>> FoldedCase("Hello World") in {s}
    True
    >>> s in {FoldedCase("Hello World")}
    True

    String inclusion works as long as the FoldedCase object
    is on the right.

    >>> "hello" in FoldedCase("Hello World")
    True

    But not if the FoldedCase object is on the left:

    >>> FoldedCase('hello') in 'Hello World'
    False

    In that case, use ``in_``:

    >>> FoldedCase('hello').in_('Hello World')
    True

    >>> FoldedCase('hello') > FoldedCase('Hello')
    False

    >>> FoldedCase('ß') == FoldedCase('ss')
    True
    """
    def __lt__(self, other) -> bool:
        ...
    
    def __gt__(self, other) -> bool:
        ...
    
    def __eq__(self, other) -> bool:
        ...
    
    def __ne__(self, other) -> bool:
        ...
    
    def __hash__(self) -> int:
        ...
    
    def __contains__(self, other): # -> bool:
        ...
    
    def in_(self, other): # -> bool:
        "Does self appear in other?"
        ...
    
    @method_cache
    def casefold(self): # -> str:
        ...
    
    def index(self, sub): # -> int:
        ...
    
    def split(self, splitter=..., maxsplit=...): # -> list[str | Any]:
        ...
    


_unicode_trap = ...
@_unicode_trap.passes
def is_decodable(value): # -> None:
    r"""
    Return True if the supplied value is decodable (using the default
    encoding).

    >>> is_decodable(b'\xff')
    False
    >>> is_decodable(b'\x32')
    True
    """
    ...

def is_binary(value): # -> bool:
    r"""
    Return True if the value appears to be binary (that is, it's a byte
    string and isn't decodable).

    >>> is_binary(b'\xff')
    True
    >>> is_binary('\xff')
    False
    """
    ...

def trim(s): # -> str:
    r"""
    Trim something like a docstring to remove the whitespace that
    is common due to indentation and formatting.

    >>> trim("\n\tfoo = bar\n\t\tbar = baz\n")
    'foo = bar\n\tbar = baz'
    """
    ...

def wrap(s): # -> str:
    """
    Wrap lines of text, retaining existing newlines as
    paragraph markers.

    >>> print(wrap(lorem_ipsum))
    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do
    eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad
    minim veniam, quis nostrud exercitation ullamco laboris nisi ut
    aliquip ex ea commodo consequat. Duis aute irure dolor in
    reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla
    pariatur. Excepteur sint occaecat cupidatat non proident, sunt in
    culpa qui officia deserunt mollit anim id est laborum.
    <BLANKLINE>
    Curabitur pretium tincidunt lacus. Nulla gravida orci a odio. Nullam
    varius, turpis et commodo pharetra, est eros bibendum elit, nec luctus
    magna felis sollicitudin mauris. Integer in mauris eu nibh euismod
    gravida. Duis ac tellus et risus vulputate vehicula. Donec lobortis
    risus a elit. Etiam tempor. Ut ullamcorper, ligula eu tempor congue,
    eros est euismod turpis, id tincidunt sapien risus a quam. Maecenas
    fermentum consequat mi. Donec fermentum. Pellentesque malesuada nulla
    a mi. Duis sapien sem, aliquet nec, commodo eget, consequat quis,
    neque. Aliquam faucibus, elit ut dictum aliquet, felis nisl adipiscing
    sapien, sed malesuada diam lacus eget erat. Cras mollis scelerisque
    nunc. Nullam arcu. Aliquam consequat. Curabitur augue lorem, dapibus
    quis, laoreet et, pretium ac, nisi. Aenean magna nisl, mollis quis,
    molestie eu, feugiat in, orci. In hac habitasse platea dictumst.
    """
    ...

def unwrap(s): # -> str:
    r"""
    Given a multi-line string, return an unwrapped version.

    >>> wrapped = wrap(lorem_ipsum)
    >>> wrapped.count('\n')
    20
    >>> unwrapped = unwrap(wrapped)
    >>> unwrapped.count('\n')
    1
    >>> print(unwrapped)
    Lorem ipsum dolor sit amet, consectetur adipiscing ...
    Curabitur pretium tincidunt lacus. Nulla gravida orci ...

    """
    ...

lorem_ipsum: str = ...
class Splitter:
    """object that will split a string with the given arguments for each call

    >>> s = Splitter(',')
    >>> s('hello, world, this is your, master calling')
    ['hello', ' world', ' this is your', ' master calling']
    """
    def __init__(self, *args) -> None:
        ...
    
    def __call__(self, s):
        ...
    


def indent(string, prefix=...):
    """
    >>> indent('foo')
    '    foo'
    """
    ...

class WordSet(tuple):
    """
    Given an identifier, return the words that identifier represents,
    whether in camel case, underscore-separated, etc.

    >>> WordSet.parse("camelCase")
    ('camel', 'Case')

    >>> WordSet.parse("under_sep")
    ('under', 'sep')

    Acronyms should be retained

    >>> WordSet.parse("firstSNL")
    ('first', 'SNL')

    >>> WordSet.parse("you_and_I")
    ('you', 'and', 'I')

    >>> WordSet.parse("A simple test")
    ('A', 'simple', 'test')

    Multiple caps should not interfere with the first cap of another word.

    >>> WordSet.parse("myABCClass")
    ('my', 'ABC', 'Class')

    The result is a WordSet, providing access to other forms.

    >>> WordSet.parse("myABCClass").underscore_separated()
    'my_ABC_Class'

    >>> WordSet.parse('a-command').camel_case()
    'ACommand'

    >>> WordSet.parse('someIdentifier').lowered().space_separated()
    'some identifier'

    Slices of the result should return another WordSet.

    >>> WordSet.parse('taken-out-of-context')[1:].underscore_separated()
    'out_of_context'

    >>> WordSet.from_class_name(WordSet()).lowered().space_separated()
    'word set'

    >>> example = WordSet.parse('figured it out')
    >>> example.headless_camel_case()
    'figuredItOut'
    >>> example.dash_separated()
    'figured-it-out'

    """
    _pattern = ...
    def capitalized(self): # -> WordSet:
        ...
    
    def lowered(self): # -> WordSet:
        ...
    
    def camel_case(self): # -> LiteralString:
        ...
    
    def headless_camel_case(self): # -> str:
        ...
    
    def underscore_separated(self): # -> LiteralString:
        ...
    
    def dash_separated(self): # -> LiteralString:
        ...
    
    def space_separated(self): # -> LiteralString:
        ...
    
    def trim_right(self, item): # -> WordSet | Self@WordSet:
        """
        Remove the item from the end of the set.

        >>> WordSet.parse('foo bar').trim_right('foo')
        ('foo', 'bar')
        >>> WordSet.parse('foo bar').trim_right('bar')
        ('foo',)
        >>> WordSet.parse('').trim_right('bar')
        ()
        """
        ...
    
    def trim_left(self, item): # -> WordSet | Self@WordSet:
        """
        Remove the item from the beginning of the set.

        >>> WordSet.parse('foo bar').trim_left('foo')
        ('bar',)
        >>> WordSet.parse('foo bar').trim_left('bar')
        ('foo', 'bar')
        >>> WordSet.parse('').trim_left('bar')
        ()
        """
        ...
    
    def trim(self, item): # -> WordSet | Self@WordSet:
        """
        >>> WordSet.parse('foo bar').trim('foo')
        ('bar',)
        """
        ...
    
    def __getitem__(self, item): # -> WordSet:
        ...
    
    @classmethod
    def parse(cls, identifier): # -> WordSet:
        ...
    
    @classmethod
    def from_class_name(cls, subject): # -> WordSet:
        ...
    


words = ...
def simple_html_strip(s): # -> str:
    r"""
    Remove HTML from the string `s`.

    >>> str(simple_html_strip(''))
    ''

    >>> print(simple_html_strip('A <bold>stormy</bold> day in paradise'))
    A stormy day in paradise

    >>> print(simple_html_strip('Somebody <!-- do not --> tell the truth.'))
    Somebody  tell the truth.

    >>> print(simple_html_strip('What about<br/>\nmultiple lines?'))
    What about
    multiple lines?
    """
    ...

class SeparatedValues(str):
    """
    A string separated by a separator. Overrides __iter__ for getting
    the values.

    >>> list(SeparatedValues('a,b,c'))
    ['a', 'b', 'c']

    Whitespace is stripped and empty values are discarded.

    >>> list(SeparatedValues(' a,   b   , c,  '))
    ['a', 'b', 'c']
    """
    separator = ...
    def __iter__(self): # -> filter[str]:
        ...
    


class Stripper:
    r"""
    Given a series of lines, find the common prefix and strip it from them.

    >>> lines = [
    ...     'abcdefg\n',
    ...     'abc\n',
    ...     'abcde\n',
    ... ]
    >>> res = Stripper.strip_prefix(lines)
    >>> res.prefix
    'abc'
    >>> list(res.lines)
    ['defg\n', '\n', 'de\n']

    If no prefix is common, nothing should be stripped.

    >>> lines = [
    ...     'abcd\n',
    ...     '1234\n',
    ... ]
    >>> res = Stripper.strip_prefix(lines)
    >>> res.prefix = ''
    >>> list(res.lines)
    ['abcd\n', '1234\n']
    """
    def __init__(self, prefix, lines) -> None:
        ...
    
    @classmethod
    def strip_prefix(cls, lines): # -> Self@Stripper:
        ...
    
    def __call__(self, line):
        ...
    
    @staticmethod
    def common_prefix(s1, s2):
        """
        Return the common prefix of two lines.
        """
        ...
    


def remove_prefix(text, prefix):
    """
    Remove the prefix from the text if it exists.

    >>> remove_prefix('underwhelming performance', 'underwhelming ')
    'performance'

    >>> remove_prefix('something special', 'sample')
    'something special'
    """
    ...

def remove_suffix(text, suffix):
    """
    Remove the suffix from the text if it exists.

    >>> remove_suffix('name.git', '.git')
    'name'

    >>> remove_suffix('something special', 'sample')
    'something special'
    """
    ...

def normalize_newlines(text): # -> str:
    r"""
    Replace alternate newlines with the canonical newline.

    >>> normalize_newlines('Lorem Ipsum\u2029')
    'Lorem Ipsum\n'
    >>> normalize_newlines('Lorem Ipsum\r\n')
    'Lorem Ipsum\n'
    >>> normalize_newlines('Lorem Ipsum\x85')
    'Lorem Ipsum\n'
    """
    ...

@functools.singledispatch
def yield_lines(iterable): # -> chain[Any]:
    r"""
    Yield valid lines of a string or iterable.

    >>> list(yield_lines(''))
    []
    >>> list(yield_lines(['foo', 'bar']))
    ['foo', 'bar']
    >>> list(yield_lines('foo\nbar'))
    ['foo', 'bar']
    >>> list(yield_lines('\nfoo\n#bar\nbaz #comment'))
    ['foo', 'baz #comment']
    >>> list(yield_lines(['foo\nbar', 'baz', 'bing\n\n\n']))
    ['foo', 'bar', 'baz', 'bing']
    """
    ...

@yield_lines.register(str)
def _(text): # -> filter[str]:
    ...

def drop_comment(line):
    """
    Drop comments.

    >>> drop_comment('foo # bar')
    'foo'

    A hash without a space may be in a URL.

    >>> drop_comment('http://example.com/foo#bar')
    'http://example.com/foo#bar'
    """
    ...

def join_continuation(lines): # -> Generator[Unknown, None, None]:
    r"""
    Join lines continued by a trailing backslash.

    >>> list(join_continuation(['foo \\', 'bar', 'baz']))
    ['foobar', 'baz']
    >>> list(join_continuation(['foo \\', 'bar', 'baz']))
    ['foobar', 'baz']
    >>> list(join_continuation(['foo \\', 'bar \\', 'baz']))
    ['foobarbaz']

    Not sure why, but...
    The character preceding the backslash is also elided.

    >>> list(join_continuation(['goo\\', 'dly']))
    ['godly']

    A terrible idea, but...
    If no line is available to continue, suppress the lines.

    >>> list(join_continuation(['foo', 'bar\\', 'baz\\']))
    ['foo']
    """
    ...

def read_newlines(filename, limit=...): # -> str | tuple[str, ...] | None:
    r"""
    >>> tmp_path = getfixture('tmp_path')
    >>> filename = tmp_path / 'out.txt'
    >>> _ = filename.write_text('foo\n', newline='', encoding='utf-8')
    >>> read_newlines(filename)
    '\n'
    >>> _ = filename.write_text('foo\r\n', newline='', encoding='utf-8')
    >>> read_newlines(filename)
    '\r\n'
    >>> _ = filename.write_text('foo\r\nbar\nbing\r', newline='', encoding='utf-8')
    >>> read_newlines(filename)
    ('\r', '\n', '\r\n')
    """
    ...

