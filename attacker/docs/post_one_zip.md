# post_one_zip
Upload a ZIP file containing samples tp be evaluated

**METHOD**: `POST`

**URL**: `https://api.mlsec.io/api/post_one_zip/new/`

**PARAMETERS**: 
* `api_token`: obtained from [https://mlsec.io/myuser](https://mlsec.io/myuser/)
* `name`: your https://mlsec.io/ username

## Successful response
**Code**: `200 OK`

## Example
`curl -X POST "https://api.mlsec.io/api/post_one_zip/new/?url=%2Fzipfile%2F&api_token=0123456789abcdef0123456789abcdef" --form "name=my_user_name" --form path=\@test_mlsc.zip`

This API use using a web form.  The HTML output should be ignored.

[Back to API](API.md)