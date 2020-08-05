# post_one_zip
Upload a ZIP file containing samples tp be evaluated. Note that only one ZIP file may be uploaded every 60 minutes. The user interface at [https://mlsec.io/zipfile/](https://mlsec.io/zipfile/new/?url=%2Fzipfile%2F) may be used in lieu of this API.

**METHOD**: `POST`

**URL**: `https://api.mlsec.io/api/post_one_zip/new/`

**PARAMETERS**: 
* `api_token`: obtained from [https://mlsec.io/myuser](https://mlsec.io/myuser/)
* `name`: a custom label for your ZIP
* `path`: local path of ZIP file to upload

## Successful response
**Code**
* `200 OK`
* Other: note hat only one ZIP file may be uploaded every 60 minutes

## Example
`curl -X POST "https://api.mlsec.io/api/post_one_zip/new/?url=%2Fzipfile%2F&api_token=0123456789abcdef0123456789abcdef" --form "name=my_label" --form path=\@test_mlsc.zip`

This API use using a web form.  The HTML output should be ignored.

[Back to API](API.md)