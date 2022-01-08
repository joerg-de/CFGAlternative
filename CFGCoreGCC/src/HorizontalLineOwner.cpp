/*
 * Copyright 2014-2022 joerg All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "HorizontalLineOwner.h"


HorizontalLineOwner::~HorizontalLineOwner()
{

}

std::vector<HorizontalLine *> *HorizontalLineOwner::getHorizontalLinesForResort()
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20--6e114003:1507706b3d9:-8000:0000000000000C15 begin
{
    return &ownedHorizontalLines;
}
// section -64--88--78-20--6e114003:1507706b3d9:-8000:0000000000000C15 end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element
