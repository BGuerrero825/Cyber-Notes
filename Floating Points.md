
Floats sacrifice precision for range. Floating values are not exact values but instead ranges of values that can float in scale depending on the exponent.

|     | Sign | Exp |     |     |     |     |     |     | Exp | Val |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     | Val |
| --- | ---- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Bit | 31   | 30  | 29  | 28  | 27  | 26  | 25  | 24  | 23  | 22  | 21  | 20  | 19  | 18  | 17  | 16  | 15  | 14  | 13  | 12  | 11  | 10  | 9   | 8   | 7   | 6   | 5   | 4   | 3   | 2   | 1   | 0   |
| Ex. | 0    | 1   | 0   | 0   | 0   | 1   | 0   | 0   | 1   | 1   | 1   | 1   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 0   | 1   |

Exponent: 2^(-126 + byte_value)
- Ex. 2^(-127 + (137)) = 2^10
Val (Mantissa): Each bit from 22 to 0 represents 2^(-23+bit_number), the mantissa is then the summation of these values + 1. A value of 1 is assumed before the first mantissa bit.
- Ex. 1110 0000 0000 0000 0000 001 = 1 + 0.5 + 0.25 + 0.125 + 0.00000011920928955078125 = 1.8750001192092896
Final Value: Mantissa \* Exponent
- 1.8750001192092896 \* 2^10 = 19.00001
