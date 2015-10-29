package oath_test

import (
	"fmt"

	"github.com/yubo/oath"
)

func Example() {
	secret := "7KZZ4VRQBX2SA6E5"
	time := int64(1446108404)

	fmt.Println(oath.Oath_otp(secret, true, 6,
		time, 30, 4))
	// Output: [234977 002761 769949 745702] <nil>
}
