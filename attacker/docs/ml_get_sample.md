# ml_get_sample
Retrieve resuts from sample submission, referenced by `jobid`

**METHOD**: `GET`

**URL**: `https://api.mlsec.io/api/get_ml_sample`

**PARAMETERS**: 
* `api_token`: obtained from [https://mlsec.io/myuser](https://mlsec.io/myuser/)
* `jobid`: `jobid` returned by a call to [ml_submit_sample](ml_submit_sample.md) or [ml_submit_sample_all](ml_submit_sample_all.md)

## Successful response
**Code**
* `200 OK`.  
* `202` if result is not yet ready

**Content**
```json
{
    "model1": {
        "result": 0
    },
    "model2": {
        "result": 1
    }
}
```


## Example
`curl -X GET "https://api.mlsec.io/api/ml_get_sample?api_token=0123456789abcdef0123456789abcdefb&jobid=736330aaa3a4683d3cc866153510763351a60062a236d22b12f4fe0f10853582"`

```json
{
    "ember": {
        "result": 0
    }
}
```

[Back to API](API.md)