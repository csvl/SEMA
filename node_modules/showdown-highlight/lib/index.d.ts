import type { ShowdownExtension } from "showdown";

declare type ShowdownHighlightOptions = {
  pre: boolean
  auto_detection: boolean
}

declare function showdownHighlight(options?: Partial<ShowdownHighlightOptions>): ShowdownExtension[];
export = showdownHighlight;
