# docs/

Drop your MGH Pocket Medicine PDF here as `mgh-handbook.pdf`.

The path is referenced from `mgh-toc.json` (`pdfPath` field), so if you use a different filename, update that too.

## Size considerations

- GitHub allows files up to 100 MB; warns above 50 MB.
- If your PDF is larger than ~50 MB, use [Git LFS](https://git-lfs.com/) or host the PDF on an external service (Cloudinary, S3, the SharePoint URL you already use, etc.) and set `pdfPath` to that URL in `mgh-toc.json`.

## Why page anchors work

Modern browsers' built-in PDF viewer (and most external ones) honor the `#page=N` fragment in URLs, e.g. `mgh-handbook.pdf#page=42` jumps straight to page 42. The Handbook tab uses this — every TOC entry opens the PDF at the right page in a new tab.

## Updating the TOC

Edit `../mgh-toc.json`. Add sections / entries with `page` numbers matching your edition. Search in the Handbook tab filters across all entries.
