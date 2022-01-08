/* ###
 * Copyright 2021-2022 joerg All Rights Reserved.
 * IP: GHIDRA
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
package cfgalternative;


import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.functiongraph.FunctionGraphPlugin;
import ghidra.app.services.BlockModelService;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;

/**
 * Sample plugin to demonstrate a plugin with a dockable GUI graph component
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ExamplesPluginPackage.NAME,
    category = PluginCategoryNames.GRAPH,
    shortDescription = "Alternative Control Flow Graph Display Plugin",
    description = "Alternative Control Flow Graph"
    ,servicesRequired = { GoToService.class, BlockModelService.class, CodeViewerService.class, ProgramManager.class }
)
//@formatter:on
public class FlowPlugin extends FunctionGraphPlugin {

    public static final String PLUGIN_OPTIONS_NAME = "AltCFG Options";
    static final String SHOW_PROVIDER_ACTION_NAME = "Display alt control flow graph";
    static final String FUNCTION_GRAPH_NAME = "Control Flow Graph";

    // Note: this help location is here to satisfy our requirement that all actions have help,
    //       but is not actual help content.  For your plugin, you must create your own content.
    /*package*/ static final HelpLocation DEFAULT_HELP =
        new HelpLocation("SampleHelpTopic", "SampleHelpTopic_Anchor_Name");

    private SampleGraphProvider provider;
    private Function currentFunction;

    public FlowPlugin(PluginTool tool) {
        super(tool);

        //FunctionManager functionManager = currentProgram.getFunctionManager();
        //currentFunction = functionManager.getFunctionContaining(currentLocation.getAddress());
        provider = new SampleGraphProvider(tool, this,null);

    }

    @Override
    protected void locationChanged(ProgramLocation location) {
        if (location == null) {
            currentFunction = null;
            return;
        }
        //dont do anything if graph is not open
        if(!provider.isVisible())
        	return;

        FunctionManager functionManager = currentProgram.getFunctionManager();
        currentFunction = functionManager.getFunctionContaining(location.getAddress());
        if (currentFunction != null)
        {
            provider.setFunction(currentFunction);
        }
    }
}