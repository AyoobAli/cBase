# cBase

<sub>[cBase v0.1.1 (Beta)]</sub>

cBase is a PHP class that can be used as a base to any class, it provides the main functions needed to start with the new class.

Simply make your class an extended class of cBase.

`NOTE:` This Class is still in Beta release. Please don't use this release in a production system.

## Install

Simply download the class `cBase.class.php` to your application directory, then include the class in your code.

```php
<?php

include "cBase.class.php";

?>
```

## Example

```php
include "cBase.class.php";

class MyClass extends cBase {

    function __construct() {

        $this->setGlobalSettings('year', date("y"));
        $this->setGlobalSettings('date', date("Y-m-d"));
        $this->setGlobalSettings('time', date("H:i:s"));
        $this->setGlobalSettings('timestamp', date("Y-m-d H:i:s"));

    }
}
```

Full documentation on how to use the class will be published soon

## License - GPLv3

Copyright (C) 2022  Ayoob Ali

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>

## Change Log

[2022-02-25] v0.1.1 (Beta):

- First Beta Release.
