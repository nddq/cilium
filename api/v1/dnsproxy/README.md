# Protocol Documentation
<a name="top"></a>

## Table of Contents

- [dnsproxy.proto](#dnsproxy-proto)
    - [DNSPolicyRule](#dnsproxy-DNSPolicyRule)
    - [DNSPolicyRules](#dnsproxy-DNSPolicyRules)
    - [DNSResponseData](#dnsproxy-DNSResponseData)
    - [FQDNMapping](#dnsproxy-FQDNMapping)
    - [FQDNSelector](#dnsproxy-FQDNSelector)
    - [MetricsData](#dnsproxy-MetricsData)
    - [ProcessingStats](#dnsproxy-ProcessingStats)
    - [Request](#dnsproxy-Request)
    - [Result](#dnsproxy-Result)
  
    - [FQDNData](#dnsproxy-FQDNData)
  
- [Scalar Value Types](#scalar-value-types)



<a name="dnsproxy-proto"></a>
<p align="right"><a href="#top">Top</a></p>

## dnsproxy.proto



<a name="dnsproxy-DNSPolicyRule"></a>

### DNSPolicyRule



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| selector_string | [string](#string) |  |  |
| port_rules | [FQDNSelector](#dnsproxy-FQDNSelector) | repeated |  |
| match_labels | [string](#string) | repeated |  |
| selections | [uint32](#uint32) | repeated |  |






<a name="dnsproxy-DNSPolicyRules"></a>

### DNSPolicyRules



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| endpoint_id | [uint64](#uint64) |  |  |
| port | [uint32](#uint32) |  |  |
| rules | [DNSPolicyRule](#dnsproxy-DNSPolicyRule) | repeated |  |
| protocol | [uint32](#uint32) |  |  |






<a name="dnsproxy-DNSResponseData"></a>

### DNSResponseData



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| response | [bool](#bool) |  |  |
| cnames | [string](#string) | repeated |  |
| qtypes | [uint32](#uint32) | repeated |  |
| answer_times | [uint32](#uint32) | repeated |  |






<a name="dnsproxy-FQDNMapping"></a>

### FQDNMapping



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| FQDN | [string](#string) |  |  |
| IPS | [bytes](#bytes) | repeated |  |
| TTL | [uint32](#uint32) |  |  |
| client_ip | [bytes](#bytes) |  |  |
| response_code | [uint32](#uint32) |  |  |
| metrics | [MetricsData](#dnsproxy-MetricsData) |  |  |
| request_id | [uint32](#uint32) |  |  |






<a name="dnsproxy-FQDNSelector"></a>

### FQDNSelector



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| match_name | [string](#string) |  |  |
| match_pattern | [string](#string) |  |  |






<a name="dnsproxy-MetricsData"></a>

### MetricsData



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| processing_stats | [ProcessingStats](#dnsproxy-ProcessingStats) |  |  |
| dns_response_data | [DNSResponseData](#dnsproxy-DNSResponseData) |  |  |
| endpoint_ip_port | [string](#string) |  |  |
| server_addr | [string](#string) |  |  |
| server_identity | [uint32](#uint32) |  |  |
| protocol | [string](#string) |  |  |
| allowed | [bool](#bool) |  |  |






<a name="dnsproxy-ProcessingStats"></a>

### ProcessingStats



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| err | [string](#string) |  |  |
| data_source | [string](#string) |  |  |






<a name="dnsproxy-Request"></a>

### Request



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| message | [string](#string) |  |  |






<a name="dnsproxy-Result"></a>

### Result



| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| success | [bool](#bool) |  |  |
| request_id | [uint32](#uint32) |  |  |





 

 

 


<a name="dnsproxy-FQDNData"></a>

### FQDNData


| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| SubscribeToDNSRules | [Request](#dnsproxy-Request) | [DNSPolicyRules](#dnsproxy-DNSPolicyRules) stream |  |
| UpdateMappings | [FQDNMapping](#dnsproxy-FQDNMapping) stream | [Result](#dnsproxy-Result) stream |  |

 



## Scalar Value Types

| .proto Type | Notes | C++ | Java | Python | Go | C# | PHP | Ruby |
| ----------- | ----- | --- | ---- | ------ | -- | -- | --- | ---- |
| <a name="double" /> double |  | double | double | float | float64 | double | float | Float |
| <a name="float" /> float |  | float | float | float | float32 | float | float | Float |
| <a name="int32" /> int32 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint32 instead. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="int64" /> int64 | Uses variable-length encoding. Inefficient for encoding negative numbers – if your field is likely to have negative values, use sint64 instead. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="uint32" /> uint32 | Uses variable-length encoding. | uint32 | int | int/long | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="uint64" /> uint64 | Uses variable-length encoding. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum or Fixnum (as required) |
| <a name="sint32" /> sint32 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int32s. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sint64" /> sint64 | Uses variable-length encoding. Signed int value. These more efficiently encode negative numbers than regular int64s. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="fixed32" /> fixed32 | Always four bytes. More efficient than uint32 if values are often greater than 2^28. | uint32 | int | int | uint32 | uint | integer | Bignum or Fixnum (as required) |
| <a name="fixed64" /> fixed64 | Always eight bytes. More efficient than uint64 if values are often greater than 2^56. | uint64 | long | int/long | uint64 | ulong | integer/string | Bignum |
| <a name="sfixed32" /> sfixed32 | Always four bytes. | int32 | int | int | int32 | int | integer | Bignum or Fixnum (as required) |
| <a name="sfixed64" /> sfixed64 | Always eight bytes. | int64 | long | int/long | int64 | long | integer/string | Bignum |
| <a name="bool" /> bool |  | bool | boolean | boolean | bool | bool | boolean | TrueClass/FalseClass |
| <a name="string" /> string | A string must always contain UTF-8 encoded or 7-bit ASCII text. | string | String | str/unicode | string | string | string | String (UTF-8) |
| <a name="bytes" /> bytes | May contain any arbitrary sequence of bytes. | string | ByteString | str | []byte | ByteString | string | String (ASCII-8BIT) |

