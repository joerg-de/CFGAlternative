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

#include "CFGEdge.h"
#include "CFGNode.h"
#include "CFGLayer.h"

#include "HorizontalLine.h"

#include <cstdlib>



CFGEdge::CFGEdge(CFGNode &src, CFGNode &dest, ConditionType cond)
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-3797976a:1506cf30996:-8000:000000000000089C begin
{
    condition = cond;
    srcNode = &src;
    src.addOutEdge(*this);
    destNode = &dest;
    dest.addInEdge(*this);

    static unsigned int next = 0;

    ID = ++next;
}
// section -64--88--78-20-3797976a:1506cf30996:-8000:000000000000089C end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

bool CFGEdge::isDown() const
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-3797976a:1506cf30996:-8000:000000000000089E begin
{
    if(srcNode->getDepth() < destNode->getDepth())
    {
        return true;
    }
    return false;
}
// section -64--88--78-20-3797976a:1506cf30996:-8000:000000000000089E end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

void CFGEdge::generateLines(std::vector<std::unique_ptr<CFGLayer> > &layer)
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-55cbe988:15071e72dc6:-8000:0000000000000BED begin
{
    //the lines should be sorted the upper first than the lower

    VerticalLine* currentVert = new VerticalLine(nullptr,*this);
    HorizontalLine* currentHorizont;
    verticalLines.push_back(std::unique_ptr<VerticalLine>(currentVert));

    int start;
    if(isDown())
        start = srcNode->getDepth();
    else
        start = destNode->getDepth() - 1;
    int i;
    for(i = 0; i < std::abs(srcNode->getDepth() - destNode->getDepth() + 1);++i) //generate the lines between
    {
        currentHorizont = new HorizontalLine(currentVert,*this);
        horizontalLines.push_back(std::unique_ptr<HorizontalLine>(currentHorizont));
        layer[start + i]->attachHorizontalLine(*currentHorizont);
        currentVert = new VerticalLine(currentHorizont,*this);
        verticalLines.push_back(std::unique_ptr<VerticalLine>(currentVert));
    }

    HorizontalLine* endhorizont = new HorizontalLine(currentVert,*this);
    horizontalLines.push_back(std::unique_ptr<HorizontalLine>(endhorizont));
    layer[start + i]->attachHorizontalLine(*endhorizont);
    VerticalLine* endvertical = new VerticalLine(endhorizont,*this);
    verticalLines.push_back(std::unique_ptr<VerticalLine>(endvertical));
}
// section -64--88--78-20-55cbe988:15071e72dc6:-8000:0000000000000BED end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

std::vector<std::unique_ptr<HorizontalLine> > *CFGEdge::getHorizontalLines()
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-55cbe988:15071e72dc6:-8000:0000000000000BEF begin
{
    return &horizontalLines;
}
// section -64--88--78-20-55cbe988:15071e72dc6:-8000:0000000000000BEF end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

std::vector<std::unique_ptr<VerticalLine> > *CFGEdge::getVerticalLines()
// don't delete the following line as it's needed to preserve source code of this autogenerated element
// section -64--88--78-20-55cbe988:15071e72dc6:-8000:0000000000000BF1 begin
{
    return &verticalLines;
}
// section -64--88--78-20-55cbe988:15071e72dc6:-8000:0000000000000BF1 end
// don't delete the previous line as it's needed to preserve source code of this autogenerated element

CFGEdge::ConditionType CFGEdge::getConditionType() const
{
    return condition;
}

CFGNode* CFGEdge::getDest()
{
    return destNode;
}

CFGNode* CFGEdge::getSrc()
{
    return srcNode;
}
auto CFGEdge::getBinding() const -> Binding
{
    return bind;
}

void CFGEdge::setBinding(Binding b)
{
    bind = b;
}
int CFGEdge::getID()
{
    return ID;
}

int CFGEdge::getLowernEndx()
{
    if(isDown())
        return destNode->getBoxCenterx();
    else
        return srcNode->getBoxCenterx();
}