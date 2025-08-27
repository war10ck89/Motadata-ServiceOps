# Login API – Fetch Bearer Token

### Endpoint: https://172.16.12.119/api/oauth/token

### Method: REST POST

## Headers

> Authorization	Basic SW50ZWdyYXRpb24tY2xpZW50OlBLdFZ4b2tFTGZhbnYza0tBV0xq

> Content-Type	multipart/form-data


## Sample Request

```
curl -k --request POST --url 'https://172.16.12.119/api/oauth/token' --header 'Authorization: Basic SW50ZWdyYXRpb24tY2xpZW50OlBLdFZ4b2tFTGZhbnYza0tBV0xq' --header 'content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' --form username=automation --form password=Pa55w0rd --form grant_type=password
```

## Sample Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbl9zc29faWQiOjAsInVzZXJfbmFtZSI6InV1aWQzNi03Y2FlODRiZi0xY2U4LTQ5YzQtYjY1Ni1iNzlkMWE5YmYzYzAiLCJzY29wZSI6WyJvdGhlci1hcGktc2NvcGUiXSwibG9naW5fc291cmNlIjoibm9ybWFsX2xvZ2luIiwiZXhwIjoxNzU2NDc3NDc3LCJsb2dpbl9tc3BfcG9ydGFsX2lkIjowLCJqdGkiOiIyMmI0ZTcyZi0yMTZiLTQ1NzMtYTZmMC0xNDljOGYxNjFkZjkiLCJjbGllbnRfaWQiOiJJbnRlZ3JhdGlvbi1jbGllbnQiLCJ0ZW5hbnRJZGVudGlmaWVyIjoiYXBvbG8ifQ.CSwVHzhLvzRymHhC4H8vOGKfsfLpbZ-rE5FoZIQEYyFZTZlOqrZteZB_HFxptiNyOeAkClqen2lK0F6MbRNv2hAw2f0e4_4rDJ_1QY1STpqsUHkE3658afOCgPjA16VVZ1zaFrz9UE6-i099tUYEuxi1gsf0oA9X0Q9bZdWKwJ6uk-708FMVtq_wEAq3TkiqVrMHcKBKXmAbe-KnSriODUF1JQMSRgw1OBpS3qVEJBdF1kYw8xiicxxCul5AxgqchIgKYFGSj1ob5YMagyvg26n1onvEIjIzlWCBLiZmiL1SnYoWadhMXPoxHa_v7NqDozSivE_3N_lthFMjvZvdWQ",
  "token_type": "bearer",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dpbl9zc29faWQiOjAsInVzZXJfbmFtZSI6InV1aWQzNi03Y2FlODRiZi0xY2U4LTQ5YzQtYjY1Ni1iNzlkMWE5YmYzYzAiLCJzY29wZSI6WyJvdGhlci1hcGktc2NvcGUiXSwiYXRpIjoiMjJiNGU3MmYtMjE2Yi00NTczLWE2ZjAtMTQ5YzhmMTYxZGY5IiwibG9naW5fc291cmNlIjoibm9ybWFsX2xvZ2luIiwiZXhwIjoxNzU2NDc3NDc3LCJsb2dpbl9tc3BfcG9ydGFsX2lkIjowLCJqdGkiOiJlOTAwM2MyZi0xNGU0LTQ0NzItOTYwNi0zNTQ1ZDdiZWIzZjkiLCJjbGllbnRfaWQiOiJJbnRlZ3JhdGlvbi1jbGllbnQiLCJ0ZW5hbnRJZGVudGlmaWVyIjoiYXBvbG8ifQ.oxV5v6PqR10oW7-rj3T5wruCl0VSSegpkR1nUsT609ESUkcpZRwG6M-EIaGBT3UhXeUTnhlgThKt_UNg9r_iJ8RP6WI8ZxfoQp9pLcYE3_hAGW-x5a7VCrff0-2Plt-nlgMwFFEEA0oQU8scTSBWoy0wJDu6qaAV-X6YP6eBh-B0rderjOhHqXKD_Z8s7exk_JFehSGhl9yY9wcpEtCd90LAdtyrdGmZj3E8osdftVHoBLlTlExCmFp8nzdxXeAnhH5LYJbP2y0wBMn2hWZh0ECEw6Vb1dILIq_4UJhO-03am2VADAynX1PGkPLH1ZYpIhvvqc_CBBorH1UuQ7OYlQ",
  "expires_in": 43199,
  "scope": "other-api-scope",
  "jti": "22b4e72f-216b-4573-a6f0-149c8f161df9"
}
```

> Extract `access_token` and prefix `Bearer `; use instead of API Key if API Key fails.


# Create Incident

### Endpoint: https://172.16.12.119/api/v1/request

### Method: REST POST

## Headers

> Authorization	Apikey s%2Bi32Ao54bKfFwiK%40XKDM5D2XNQpe4i%2FUB3eK8mWOcseqp3rDyaQ%3D

> Content-Type	application/json


## Sample Request

```
curl -k --request POST --url 'https://172.16.12.119/api/v1/request' --header 'Authorization: Apikey s%2Bi32Ao54bKfFwiK%40XKDM5D2XNQpe4i%2FUB3eK8mWOcseqp3rDyaQ%3D' --header 'content-type: application/json' --data-raw '{"customField":{"New Multi-Select Dropdown":["A","C"],"New Datetime":1756304676767},"requesterEmail":"paulsn","subject":"Incident Summary","description":"<p>Incident Description</p>","departmentName":"Department","impactName":"Low","urgencyName":"Low","categoryName":"Incident Category","source":"Email","locationName":"Ahmedabad","priorityName":"Low"}'
```

## Sample Response

```json
{"id":65,"categoryName":"Incident Category","name":"INC-46","createdTime":1756304677751,"updatedTime":1756304677751,"departmentName":"Department","customField":{"WSR Sent":"","New Checkbox":[],"Project Ticket ID":"","Count of WSR Sent":0.0,"WSR Status":"","Delivery Ticket Internal ID":"","New Text Area":"","New Datetime":1756304676767,"New Text Input":"","New Rich Text Area":"","Delivery Ticket ID":"","New Dropdown":"","New Number":0.0,"New Radio":"","Project Ticket Internal ID":"","New Multi-Select Dropdown":["A","C"]},"statusName":"Open","createdByName":"Automation","subject":"Incident Summary","requesterName":"Snehashis Paul","fileAttachments":[],"requesterEmail":"snehashis.paul@motadata.com","description":"Incident Description","locationName":"Ahmedabad","impactName":"Low","priorityName":"Low","urgencyName":"Low","updatedByName":"Automation","source":"Email","spam":false,"supportLevel":"tier0"}
```

# Create Service Request

### Endpoint: https://172.16.12.119/api/v1/service_catalog/servicerequest

### Method: REST POST

## Headers

> Authorization	Apikey s%2Bi32Ao54bKfFwiK%40XKDM5D2XNQpe4i%2FUB3eK8mWOcseqp3rDyaQ%3D

> Content-Type	application/json


## Sample Request

```
curl -k --request POST --url 'https://172.16.12.119/api/v1/service_catalog/servicerequest' --header 'Authorization: Apikey s%2Bi32Ao54bKfFwiK%40XKDM5D2XNQpe4i%2FUB3eK8mWOcseqp3rDyaQ%3D' --header 'content-type: application/json' --data-raw '{"customField":{"New Text Area":"Text data","New Checkbox":["C","B"],"New Datetime":1756304677083},"requester":"paulsn","description":"<p>SR Description</p>","departmentName":"Department","impactName":"Low","urgencyName":"Low","categoryName":"SR Category","source":"Email","locationName":"Ahmedabad","priorityName":"Low","serviceName":"HW 1","serviceCategoryName":"Hardware"}'
```

## Sample Response

```json
{"id":66,"name":"SR-47","createdTime":1756304678069,"updatedTime":1756304678154,"departmentName":"Department","customField":{"WSR Sent":"","New Checkbox":[],"Project Ticket ID":"","Count of WSR Sent":0.0,"WSR Status":"","Delivery Ticket Internal ID":"","New Text Area":"","New Datetime":0,"New Text Input":"","New Rich Text Area":"","Delivery Ticket ID":"","New Dropdown":"","New Number":0.0,"New Radio":"","Project Ticket Internal ID":"","New Multi-Select Dropdown":[]},"statusName":"Open","createdByName":"Automation","subject":"---","requesterName":"Snehashis Paul","fileAttachments":[],"requesterEmail":"snehashis.paul@motadata.com","description":"","locationName":"Ahmedabad","impactName":"Low","priorityName":"Low","urgencyName":"Low","updatedByName":"Automation","source":"External","spam":false,"supportLevel":"tier0"}
```
