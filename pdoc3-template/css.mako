<%!
    from pdoc.html_helpers import minify_css
    import os

    color_bg = '#0D0D0D'
    color_cb = '#000000'
    color_fg = '#EEEEEE'
    color_h1 = '#EE8080'
    color_h2 = '#BB4040'
    color_hlink = color_h1
    color_hover = color_fg
    color_admonition_problem = '#300000'
    color_admonition_warning = '#998800'
    color_admonition_neutral = '#054000'

    def getfont(module):
      if module_path := module.obj.__file__:
        path = os.path.dirname(module_path)         
      else:
        path = os.path.abspath(os.path.curdir)
      font = 'FixedSysEx.ttf'
      name = ''
      while True:
        name = os.path.basename(path)
        if name == 'refinery':
          return font
        path = os.path.dirname(path)
        font = '../{}'.format(font)
%>

<%def name="mobile()" filter="minify_css">
  .flex {
    display: flex !important;
  }

  body {
    background-color: ${color_bg};
    color: ${color_fg};
    font-size: 16pt;
  }

  @font-face {
    font-family: "FixedSysEx";
    src:
      local('Fixedsys Excelsior 3.01-L2'),
      local('Fixedsys Excelsior 3.01'),
      local('FixedSysEx'),
      url(${getfont(module)}) format('truetype')
  }
  
  code, pre, body, html {font-family: FixedSysEx, monospace;}
  b, strong { font-weight: normal }


  #content {
    padding: 20px;
  }

  #sidebar {
    padding: 1vw;
    overflow: hidden;
  }

  .http-server-breadcrumbs {
    font-size: 130%;
    margin: 0 0 15px 0;
  }

  #footer {
    font-size: .75em;
    padding: 5px 30px;
    border-top: 1px solid ${color_fg};
    text-align: right;
  }
    #footer p {
      margin: 0 0 0 1em;
      display: inline-block;
    }
    #footer p:last-child {
      margin-right: 30px;
    }

  h1, h2, h3, h4, h5 {
    font-weight: 300;
  }
  hr {
    display: none;
  }
  h1 {
    font-size: 2.5em;
    line-height: 1.1em;
  }
  h2 {
    font-size: 1.75em;
    margin: 1em 0 .50em 0;
  }
  h3 {
    font-size: 1.4em;
    margin: 25px 0 10px 0;
  }
  h4 {
    margin: 0;
    font-size: 105%;
  }

  a {
    color: ${color_hlink};
    text-decoration: none;
    transition: color .3s ease-in-out;
  }
  a:hover {
    color: ${color_hover};
  }

  // .title code { font-weight: bold; }
  h2[id^="header-"] {
    margin-top: 2em;
  }
  .ident {
    color: ${color_h2};
  }

  pre code {
    background: ${color_cb};
    display: block;
    padding: 1px 0px 4px 0px;
    line-height: 100%;
  }
  code {
    background: ${color_cb};
    padding: 1px 0px;
    overflow-wrap: break-word;
  }
  h1 code { background: transparent }

  pre {
    background: ${color_cb};
    border: 0;
    border-top: 1px solid ${color_fg};
    border-bottom: 1px solid ${color_fg};
    margin: 1em 0;
    padding: 1ex;
    overflow-x: auto
  }

  #http-server-module-list {
    display: flex;
    flex-flow: column;
  }
    #http-server-module-list div {
      display: flex;
    }
    #http-server-module-list dt {
      min-width: 10%;
    }
    #http-server-module-list p {
      margin-top: 0;
    }

  .toc ul,
  #index {
    list-style-type: none;
    margin: 0;
    padding: 0;
  }
    #index code {
      background: transparent;
    }
    #index ul {
      list-style-type: square;
      padding: 0;
    }
    // #index h4 { font-weight: bold; }
    #index h4 + ul {
      margin-bottom:.6em;
    }


  dl {
    margin-bottom: 2em;
  }
    dl dl:last-child {
      margin-bottom: 4em;
    }
  dd {
    margin: 0 0 1em 10px;
  }
    #header-classes + dl > dd {
      margin-bottom: 3em;
    }
    dd dd {
      margin-left: 2em;
    }
    dd p {
      margin: 10px 0;
    }
    .name {
      background: ${color_cb};
      padding: 5px 10px;
      display: inline-block;
      min-width: 40%;
    }
      .name:hover {
        background: ${color_bg};
      }
      .name > span:first-child {
        white-space: nowrap;
      }
      .name.class > span:nth-child(2) {
        margin-left: .4em;
      }
    .inherited {
      color: ${color_fg};
      border-left: 5px solid ${color_fg};
      padding-left: 1em;
    }
    .inheritance em {
      font-style: normal;
    }

    /* Docstrings titles, e.g. in numpydoc format */
    .desc h2 {
      font-weight: 400;
      font-size: 1.25em;
    }
    .desc h3 {
      font-size: 1em;
    }
    .desc dt code {
      background: inherit;  /* Don't grey-back parameters */
    }

    .source summary,
    .git-link-div {
      color: #666;
      text-align: right;
      font-weight: 400;
      font-size: .8em;
      text-transform: uppercase;
    }
      .source summary > * {
        white-space: nowrap;
        cursor: pointer;
      }
      .git-link {
        color: inherit;
        margin-left: 1em;
      }
    .source pre {
      max-height: 500px;
      overflow: auto;
      margin: 0;
    }
    .source pre code {
      overflow: visible;
    }
  .hlist {
    list-style: none;
  }
    .hlist li {
      display: inline;
    }
    .hlist li:after {
      content: ',\2002';
    }
    .hlist li:last-child:after {
      content: none;
    }
    .hlist .hlist {
      display: inline;
      padding-left: 1ch;
    }

  img {
    max-width: 100%;
  }

  .admonition {
    padding: .1em .5em;
    margin-bottom: 1em;
  }
    .admonition.note,
    .admonition.info,
    .admonition.todo,
    .admonition.versionadded,
    .admonition.important,
    .admonition.tip,
    .admonition.hint {
      background: ${color_admonition_neutral};
    }
    .admonition.warning,
    .admonition.versionchanged,
    .admonition.deprecated {
      background: ${color_admonition_warning};
    }
    .admonition.error,
    .admonition.danger,
    .admonition.caution {
      background: ${color_admonition_problem};
    }
</%def>

<%def name="desktop()" filter="minify_css">
  @media screen and (min-width: 700px) {
    #sidebar {
      width: 30%;
    }
    #content {
      width: 70%;
      max-width: 100ch;
      padding: 1vw;
    }
    main {
      display: flex;
      flex-direction: row;
      justify-content: flex-end;
    }
    .toc ul ul,
    #index ul {
      padding-left: 1.5em;
    }
    .toc > ul > li {
      margin-top: .5em;
    }
  }
</%def>

<%def name="print()" filter="minify_css">
@media print {
  #sidebar h1 {
    page-break-before: always;
  }
  .source {
    display: none;
  }
}
@media print {
    * {
        background: transparent !important;
        color: #000 !important; /* Black prints faster: h5bp.com/s */
        box-shadow: none !important;
        text-shadow: none !important;
    }

    a[href]:after {
        content: " (" attr(href) ")";
        font-size: 90%;
    }
    /* Internal, documentation links, recognized by having a title,
       don't need the URL explicity stated. */
    a[href][title]:after {
        content: none;
    }

    abbr[title]:after {
        content: " (" attr(title) ")";
    }

    /*
     * Don't show links for images, or javascript/internal links
     */

    .ir a:after,
    a[href^="javascript:"]:after,
    a[href^="#"]:after {
        content: "";
    }

    pre,
    blockquote {
        border: 1px solid ${color_fg};
        page-break-inside: avoid;
    }

    thead {
        display: table-header-group; /* h5bp.com/t */
    }

    tr,
    img {
        page-break-inside: avoid;
    }

    img {
        max-width: 100% !important;
    }

    @page {
        margin: 0.5cm;
    }

    p,
    h2,
    h3 {
        orphans: 3;
        widows: 3;
    }

    h1,
    h2,
    h3,
    h4,
    h5,
    h6 {
        page-break-after: avoid;
    }
}
</%def>
