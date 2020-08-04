# ml_submit_sample_all
Submit a sample to all hosted ML models, and retrieve a `jobid`

**METHOD**: `POST`

**URL**: `https://api.mlsec.io/api/ml_submit_sample_all`

**PARAMETERS**: 
* `api_token`, obtained from [https://mlsec.io/myuser](https://mlsec.io/myuser/).

## Successful response
**Code**: `200 OK`

**Content**
```json
{
    "jobid": "{jobid}"
}
```

## Example
`curl -X POST https://api.mlsec.io/api/ml_submit_sample_all?api_token=0123456789abcdef0123456789abcdef --data-binary @putty.exe`

```json
{
    "jobid": "db9616e0254b9187a42711fe2a68b6e29657b5d73aa3394392384b6354132dd1"
}
```


[Back to API](API.md)