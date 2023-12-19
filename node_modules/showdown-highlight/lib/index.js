"use strict";

var decodeHtml = require("html-encoder-decoder").decode,
    showdown = require("showdown"),
    hljs = require("highlight.js"),
    classAttr = 'class="';

/**
 * showdownHighlight
 * Highlight the code in the showdown input.
 *
 * Examples:
 *
 * ```js
 * let converter = new showdown.Converter({
 *     extensions: [showdownHighlight]
 * })
 * ```
 *
 * Enable the classes in the `<pre>` element:
 *
 * ```js
 * let converter = new showdown.Converter({
 *     extensions: [showdownHighlight({ pre: true })]
 * })
 * ```
 *
 *
 * If you want to disable language [auto detection](https://highlightjs.org/usage/)
 * feature of hljs, change `auto_detection` flag as `false`. With this option
 * turned off, `showdown-highlight` will not process any codeblocks with no
 * language specified.
 *
 * ```js
 * let converter = new showdown.Converter({
 *     extensions: [showdownHighlight({ auto_detection: false })]
 * })
 * ```
 *
 * @name showdownHighlight
 * @function
 */
module.exports = function showdownHighlight() {
    var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
        _ref$pre = _ref.pre,
        pre = _ref$pre === undefined ? false : _ref$pre,
        _ref$auto_detection = _ref.auto_detection,
        auto_detection = _ref$auto_detection === undefined ? true : _ref$auto_detection;

    var filter = function filter(text, converter, options) {
        var params = {
            left: "<pre><code\\b[^>]*>",
            right: "</code></pre>",
            flags: "g"
        };

        var replacement = function replacement(wholeMatch, match, left, right) {
            match = decodeHtml(match);

            var lang = (left.match(/class=\"([^ \"]+)/) || [])[1];

            if (!lang && !auto_detection) {
                return wholeMatch;
            }

            if (left.includes(classAttr)) {
                var attrIndex = left.indexOf(classAttr) + classAttr.length;
                left = left.slice(0, attrIndex) + 'hljs ' + left.slice(attrIndex);
            } else {
                left = left.slice(0, -1) + ' class="hljs">';
            }

            if (pre && lang) {
                left = left.replace('<pre>', "<pre class=\"" + lang + " language-" + lang + "\">");
            }

            if (lang && hljs.getLanguage(lang)) {
                return left + hljs.highlight(match, { language: lang }).value + right;
            }

            return left + hljs.highlightAuto(match).value + right;
        };

        return showdown.helper.replaceRecursiveRegExp(text, replacement, params.left, params.right, params.flags);
    };

    return [{
        type: "output",
        filter: filter
    }];
};