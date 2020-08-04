# get_all_sample
Query the status of uploaded samples

**METHOD**: `GET`

**URL**: `https://api.mlsec.io/api/get_all_sample/`

**PARAMETERS**: 
* `api_token`: obtained from [https://mlsec.io/myuser](https://mlsec.io/myuser/)

## Successful response
**Code**: `200 OK`

## Example
`curl -X GET https://api.mlsec.io/api/get_all_sample/?api_token=0123456789abcdef0123456789abcdef`

```
[ 
    {
        "errors": "ML process error.",
        "id": 36,
        "ioc": "",
        "ioc_processed": "False",
        "ml1_bypassed": "False",
        "ml2_bypassed": "False",
        "ml3_bypassed": "False",
        "ml_job_id": "0123456789abcdef",
        "ml_processed": "False",
        "name": 50,
        "sample_score": 0,
        "sandbox_equivalent": "False",
        "sbx_job_id": 0,
        "sbx_sample_id": 0,
        "sbx_submission_id": 0,
        "sha256": "0123456789abcdef",
        "uploader_id": {
            "errors": "None",
            "id": 1,
            "name": "name",
            "path": "Jane.Doe_AT_microsoft.com_1596580794.7931645.zip",
            "process_status": "processing_sandbox",
            "uploader_id": 6327,
            "uploadtime": "2020-08-04 22:39"
        },
        "valid_new_PE": "True"
    }
]
```

[Back to API](API.md)