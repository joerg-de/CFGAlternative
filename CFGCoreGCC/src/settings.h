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

#ifndef SETTINGS
#define SETTINGS

static const unsigned int horizontalLineOffset = 10; //this is the space between the lines when they are Horizontal

static const unsigned int IOhorizontalLineOffset = 10; //this is the space between the lines when they go out and come into a Node

static const unsigned int InVerticalLineOffset = 10; //this is the space between the lines when they go out and come into a Node

static const unsigned int verticalNodeOffset = 10; //this is the space between 2 Nodes Vertical

static const unsigned int horizontalverticalNodeOffset = 10; //this is the space between 2 Nodes Horizontal

//time stuff
#ifdef NDEBUG
#define STARTTIMEANA(x) ((void)0)
#define TAKETIMEANA(x,y) ((void)0)
#else

#define STARTTIMEANA(x) \
    std::chrono::steady_clock::time_point t##x = std::chrono::steady_clock::now();

#define TAKETIMEANA(x,y) \
    std::chrono::duration<double> time_span = std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::steady_clock::now() - t##x); \
    /*qDebug() << x << "took me " << time_span.count() << " seconds.";*/
#endif

#endif // SETTINGS

