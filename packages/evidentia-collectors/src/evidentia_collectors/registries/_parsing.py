"""Keep source, request and complete-result JSON admission separate."""

from evidentia_collectors.enterprise_retention._parsing import (
    JsonObject as JsonObject,
)
from evidentia_collectors.enterprise_retention._parsing import (
    ParsingError as ParsingError,
)
from evidentia_collectors.enterprise_retention._parsing import (
    canonical_json as canonical_json,
)
from evidentia_collectors.enterprise_retention._parsing import (
    checked_json as checked_json,
)
from evidentia_collectors.enterprise_retention._parsing import (
    checked_result_json as checked_result_json,
)
from evidentia_collectors.enterprise_retention._parsing import (
    parse_result_json as parse_result_json,
)
from evidentia_collectors.enterprise_retention._parsing import (
    parse_strict_json as parse_strict_json,
)
from evidentia_collectors.enterprise_retention._parsing import (
    result_json_bytes as result_json_bytes,
)

REQUEST_BYTE_LIMIT = 65_536
SOURCE_BYTE_LIMIT = 1_048_576
OBSERVATION_BYTE_LIMIT = 65_536
RESULT_BYTE_LIMIT = 4_194_304
