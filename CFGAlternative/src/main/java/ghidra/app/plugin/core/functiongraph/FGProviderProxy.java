/* ###
 * Copyright 2021-2022 joerg All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ghidra.app.plugin.core.functiongraph;

import ghidra.program.model.listing.Program;

public class FGProviderProxy extends FGProvider {

    public FGProviderProxy(FunctionGraphPlugin plugin, boolean isConnected) {
        super(plugin, isConnected);
    }

    public void doSetProgram(Program newProgram) {
        super.doSetProgram(newProgram);
    }

}
