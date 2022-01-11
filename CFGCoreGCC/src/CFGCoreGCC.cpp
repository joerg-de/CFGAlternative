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

#include <iostream>
#include <windows.h>
#include <stdio.h>
#define _PIPE_NAME  TEXT("\\\\.\\pipe\\CFGPipe3953956285")

#include "CFG.h"
#include "CFGEdge.h"
#include "settings.h"

using namespace std;


#pragma pack(push, 1)
struct NodeInfoStruct
{
	float width;
	float height;
};
struct NodeInfoStructBack
{
	int x;
	int y;
};
struct EdgeInfoStructBack
{
	int x1;
	int x2;
	int y;
};
struct EdgeInfoStruct
{
	unsigned int start;
	unsigned int end;
	unsigned int cond_type;
};
#pragma pack(pop)

int main() {

	//handel Stuff
    HANDLE hPipe;
    DWORD dwRead;
    hPipe = CreateNamedPipe(_PIPE_NAME,
                            PIPE_ACCESS_DUPLEX,
                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,   // FILE_FLAG_FIRST_PIPE_INSTANCE is not needed but forces CreateNamedPipe(..) to fail if the pipe already exists...
                            1,
                            1024 * 64,
                            1024 * 64,
                            NMPWAIT_USE_DEFAULT_WAIT,
                            NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
		printf("CreateNamedPipe Error. (%lu)", GetLastError());
		return -1;
    }
    while (true)
    {
        if (ConnectNamedPipe(hPipe, NULL) == FALSE)   // wait for someone to connect to the pipe
        {
    		printf("ConnectNamedPipe Error. (%lu)", GetLastError());
    		return -1;
        }
        {
        	CFG cfg;
        	unsigned int numNodes;
        	if (ReadFile(hPipe, &numNodes, sizeof(numNodes), &dwRead, NULL) == FALSE || sizeof(numNodes) != dwRead)
        	{
        		printf("pipe Error get numNodes. (%lu)", GetLastError());
        		return -1;
        	}
        	NodeInfoStruct * str1 = (NodeInfoStruct *)malloc(sizeof(NodeInfoStruct)*numNodes);
        	if (!str1)
        	{
        		printf("malloc Error. (%lu)", GetLastError());
        		return -1;
        	}
        	if (ReadFile(hPipe, str1, sizeof(NodeInfoStruct)*numNodes , &dwRead, NULL) == FALSE || dwRead != sizeof(NodeInfoStruct)*numNodes)
        	{
        		printf("pipe Error get Nodes. (%lu)", GetLastError());
        		return -1;
        	}
        	for (unsigned int i = 0; i < numNodes;i++)
        	{
        		CFGNode *node = new CFGNode(str1[i].width, str1[i].height + InVerticalLineOffset, i);
        		cfg.addNode(*node);
        	}
        	free(str1);

        	unsigned int numEdges;
        	if (ReadFile(hPipe, &numEdges, sizeof(numEdges), &dwRead, NULL) == FALSE || sizeof(numEdges) != dwRead)
        	{
        		printf("pipe Error get numEdges. (%lu)", GetLastError());
        		return -1;
        	}
        	EdgeInfoStruct * str2 = (EdgeInfoStruct *)malloc(sizeof(EdgeInfoStruct)*numEdges);
        	if (!str2)
        	{
        		printf("malloc Error. (%lu)", GetLastError());
        		return -1;
        	}
        	if (ReadFile(hPipe, str2, sizeof(EdgeInfoStruct)*numEdges , &dwRead, NULL) == FALSE || dwRead != sizeof(EdgeInfoStruct)*numEdges)
        	{
        		printf("pipe Error get Edges. (%lu)", GetLastError());
        		return -1;
        	}
        	for (unsigned int i = 0; i < numEdges;i++)
        	{
        		CFGEdge *edge = new CFGEdge(*cfg.getNodes()->at(str2[i].start), *cfg.getNodes()->at(str2[i].end), static_cast<CFGEdge::ConditionType>(str2[i].cond_type));
        		cfg.addEdge(*edge);
        	}
        	free(str2);

        	//compute
        	unsigned int startID;
        	if (ReadFile(hPipe, &startID, sizeof(startID), &dwRead, NULL) == FALSE || sizeof(startID) != dwRead)
        	{
        		printf("pipe Error get numEdges. (%lu)", GetLastError());
        		return -1;
        	}
        	cfg.solve(*cfg.getNodes()->at(startID));

        	//send back
        	std::vector<CFGNode *> *Nodes = cfg.getNodes();
        	for(CFGNode * elem: *Nodes)
        	{
        		NodeInfoStructBack s;
        		s.x = elem->getx();
        		s.y = elem->gety() + InVerticalLineOffset;
            	if (WriteFile(hPipe, &s, sizeof(s), &dwRead, NULL) == FALSE || sizeof(s) != dwRead)
            	{
            		printf("pipe Error send Node. (%lu)", GetLastError());
            		return -1;
            	}
        	}

        	std::vector<CFGEdge *> edges;
        	for(CFGNode * elem: *Nodes)
        	{
        		edges.insert(edges.end(),elem->getOutEdges()->begin(),elem->getOutEdges()->end());
        	}

    		unsigned int edgesNum = edges.size();
			if (WriteFile(hPipe, &edgesNum, sizeof(edgesNum), &dwRead, NULL) == FALSE || sizeof(edgesNum) != dwRead)
			{
				printf("pipe Error send edgesNum. (%lu)", GetLastError());
				return -1;
			}


        	for(CFGEdge * elem: edges)
        	{
        		unsigned int num = elem->getVerticalLines()->size() - 1;
				if (WriteFile(hPipe, &num, sizeof(num), &dwRead, NULL) == FALSE || sizeof(num) != dwRead)
				{
					printf("pipe Error send EdgeSize. (%lu)", GetLastError());
					return -1;
				}
				CFGNode* src = elem->getSrc();
				CFGNode* dest = elem->getDest();
				int idt = src->getID();
				if (WriteFile(hPipe, &idt, sizeof(idt), &dwRead, NULL) == FALSE || sizeof(idt) != dwRead)
				{
					printf("pipe Error send Src. (%lu)", GetLastError());
					return -1;
				}
				idt = dest->getID();
				if (WriteFile(hPipe, &idt, sizeof(idt), &dwRead, NULL) == FALSE || sizeof(idt) != dwRead)
				{
					printf("pipe Error send Dest. (%lu)", GetLastError());
					return -1;
				}

				if (elem->isDown())
				{
					auto currentline = elem->getVerticalLines()->begin();
					while(true)
					{
						EdgeInfoStructBack s;
						s.y = (*currentline)->getLowery();
						s.x1 = (*currentline)->getx();
						++currentline;
						if(currentline == elem->getVerticalLines()->end())
							break;
						s.x2 = (*currentline)->getx();

						if (WriteFile(hPipe, &s, sizeof(s), &dwRead, NULL) == FALSE || sizeof(s) != dwRead)
						{
							printf("pipe Error send Edge. (%lu)", GetLastError());
							return -1;
						}
					}
				}
				else
				{
					auto currentline = elem->getVerticalLines()->rbegin();
					while(true)
					{
						EdgeInfoStructBack s;
						s.y = (*currentline)->getUppery();
						s.x1 = (*currentline)->getx();
						++currentline;
						if(currentline == elem->getVerticalLines()->rend())
							break;
						s.x2 = (*currentline)->getx();

						if (WriteFile(hPipe, &s, sizeof(s), &dwRead, NULL) == FALSE || sizeof(s) != dwRead)
						{
							printf("pipe Error send Edge. (%lu)", GetLastError());
							return -1;
						}
					}
				}
        	}
			//cleanup
			for (auto i : *cfg.getEdges())
				delete i;
			for (auto i : *cfg.getNodes())
				delete i;

        	if (!FlushFileBuffers(hPipe)) {
        		printf("FlushFileBuffers failed. (%lu)", GetLastError());
        		return -1;
        	}
        	if (!DisconnectNamedPipe(hPipe)) {
        		printf("DisconnectNamedPipe failed. (%lu)", GetLastError());
        		return -1;
        	}
        }
    }

    return 0;
}
