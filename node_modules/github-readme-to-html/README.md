# GitHub Readme to HTML Static Site

NPM module to convert GitHub markdown to HTML with GitHub-like styling and static assets. Output is ready to serve via static file hosting like Netlify with a push of a button.

### Install

```
npm install github-readme-to-html
```

### Run

```
Usage: npx github-readme-to-html [options]

Options:
  -i, --input <filename>   The input readme/markdown file (default: "README.md")
  -o, --output <filename>  The output HTML file (default: "index.html")
  -t, --title <title>      The page title (default: "Read Me")
  -h, --help               display help for command
```

### Output

All output goes to ./dist

```
- dist/
  - index.html
  - assets/
    - .
    - .
    - .
```

### Example

Input: [ORIGINAL.md](ORIGINAL.md)

Output: https://github-readme-to-html.netlify.app/

### Testing
To test local changes:
```
node ./index.js 
```

### Change Log

- 1.0.9 - jrnewton/github-readme-to-html#9 - highlightjs support
- 1.0.8 - update dependency
- 1.0.7 - jrnewton/github-readme-to-html#5 - fix newline issue when using yarn
- 1.0.6 - jrnewton/github-readme-to-html#3 - footnote support
- 1.0.5 - jrnewton/github-readme-to-html#4 - resize image support
- 1.0.4 - jrnewton/github-readme-to-html#2 - output filename support

---

This project is based on https://github.com/KrauseFx/markdown-to-html-github-style
