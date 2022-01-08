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

#ifndef CFGEdge_h
#define CFGEdge_h

#include <memory>
#include <vector>


class HorizontalLine;
class VerticalLine;
class CFGNode;
class CFGLayer;


class CFGEdge {

public:
    enum class Binding
    {
        None,
        Right,
        Left,
        NotSet
    };
    enum class ConditionType
    {
        None,
        True,
        False,
        Switch,
        Other
    };



    CFGEdge(CFGNode& src, CFGNode& dest,ConditionType cond);

    bool isDown() const;

	void generateLines(std::vector<std::unique_ptr<CFGLayer>>& layer);

    std::vector<std::unique_ptr<HorizontalLine> > *getHorizontalLines();

    std::vector<std::unique_ptr<VerticalLine>> *getVerticalLines();

    ConditionType getConditionType() const;

    CFGNode* getDest();

    CFGNode* getSrc();

    Binding getBinding() const;

    void setBinding(Binding b);

    int getLowernEndx();

    int getID();


private:
    CFGNode* srcNode;
    CFGNode* destNode;
    Binding bind = Binding::NotSet;
    ConditionType condition;
    std::vector< std::unique_ptr<HorizontalLine> > horizontalLines;
    std::vector< std::unique_ptr<VerticalLine> > verticalLines;
    unsigned int ID;
};

#endif // CFGEdge_h
