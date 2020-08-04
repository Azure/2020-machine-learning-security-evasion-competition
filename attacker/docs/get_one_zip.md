# get_one_zip
Query the status of ZIP file

**METHOD**: `GET`

**URL**: `https://api.mlsec.io/api/get_one_zip/<ID>`

**PARAMETERS**: 
* `<ID>`: obtained from `r["uploader_id"]["id"]` from [get_all_sample](get_all_sample.md)
* `api_token`: obtained from [https://mlsec.io/myuser](https://mlsec.io/myuser/)

## Successful response
**Code**: `200 OK`

## Example
`curl -X GET https://api.mlsec.io/api/get_one_zip/1?api_token=0123456789abcdef0123456789abcdef`

```
{"errors":null,"id":1,"name":"name","path":"Jane.Doe_AT_microsoft.com_1596580794.7931645.zip","process_status":"processing_sandbox","uploader_id":6327,"uploadtime":"2020-08-04 22:39"}
```

[Back to API](API.md)