# CTFd-Classify-On-Register-Plugin
### V1.0.3 BETA
This is a CTFd platform plugin that retrieves and sets classification when a user registers. This plugin is specifically tailored to register Texas A&M Students for TAMUctf, Texas A&M's CTFd plateform instance.

### *DISCLAIMER*
The [CTFd-Classified-Scoreboard](https://github.com/tamuctf/ctfd-classified-scoreboard-plugin) Plugin must be previously installed before this plugin will work. Specifically, the files from the Scoreboard plugin must be placed within the plugin directory.

Because the previously mentioned Scoreboard plugin messes with the database, the (Root Directory)\CTFd\CTFd.db file must be deleted before the CTFd instance can be sucessfully started after installing it. With that said, this plugin should be able to be installed without needing to delete the CTFd.db file if the previously mentioned Scoreboard plugin has been successfully installed, as the dependent databases will have already been installed.

# Usage:
This particular plugin is done all automatically, so there is not anyway to alter the functionality of the plugin except through changing the __init__.py file that exists in the plugin directory or the register.html in this plugin folder.

# Repurposing to Another Organization
Although this plugin is specifically tailored to TAMUctf, this plugin can be repurposed for other organizations to be automatically classified.




