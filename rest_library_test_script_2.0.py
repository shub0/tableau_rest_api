from tableau_rest_api.tableau_rest_api import *
import urllib2
import time

tableau_server_version = u"9.2"

# Use your own server credentials
username = ''
password = ''
server = 'http://127.0.0.1'
default = TableauRestApi(server, username, password, 'default', tableau_server_version=tableau_server_version)
logger = Logger('rest_example_9_2.log')
default.enable_logging(logger)

default.signin()

new_site_name = 'Test Site'
new_site_content_url = 'tsite'
try:
    # Determine if site exists with current name. Delete if it does.
    # Then create new site with the same name and contentUrl
    try:
        delete_login_content_url = default.query_site_content_url_by_site_name('Test Site 2')
        print 'Received content_url to delete ' + delete_login_content_url
        test_site = TableauRestApi(server, username, password, delete_login_content_url, tableau_server_version=tableau_server_version)
        test_site.enable_logging(logger)
        test_site.signin()
        print 'Signed in successfully to ' + delete_login_content_url

        print 'Querying the current site'
        site_xml = test_site.query_current_site()
        print site_xml

        print 'Attempting to delete current site'
        test_site.delete_current_site()
        print "Deleted site " + new_site_name
    except NoMatchFoundException as e:
        print e.msg
        print "Cannot delete site that does not exist"
    except Exception as e:
        raise

    try:
        # Create the new site
        print 'Now going into the create site'
        default.log('Logging with the log function')
        new_site_id = default.create_site(new_site_name, new_site_content_url)
        print 'Created new site ' + new_site_id
    except AlreadyExistsException as e:
        print e.msg
        print "Cannot create new site, exiting"
        exit()
    except Exception as e:
        raise

    # Once we've created the site, we need to sign into it to do anything else
    test_site = TableauRestApi(server, username, password, new_site_content_url, tableau_server_version=tableau_server_version)
    test_site.enable_logging(logger)
    try:
        test_site.signin()
        # Add groups and users to the site
        print 'Signed in successfully to ' + new_site_content_url

        # Update the site name
        print 'Updating site name'
        test_site.update_current_site('Test Site 2')

        projects_to_create = ['Sandbox', 'Approved Datasources', 'Production']
        for project in projects_to_create:
            print "Creating Project '" + project + "'"
            new_proj_luid = test_site.create_project(project)
        
        groups_to_create = ['Publishers', 'Site Admins', 'Super Admins', 'Sales', 'Marketing', 'IT', 'VPs']
        for group in groups_to_create:
            print "Creating Group '" + group + "'"
            new_group_luid = test_site.create_group(group)
            print "updating the group name"
            time.sleep(2)
            test_site.update_group_by_luid(new_group_luid, group + ' (updated)')
        
        print "Sleeping 1 second for group creation to finish"
        # It does take a second for the indexing to update, so if you've made a lot of changes, pause for 1 sec
        time.sleep(1)

        print "Get all the groups"
        groups_on_site = test_site.query_groups()
        # Assign permissions on each project, for each group

        print "Converting the groups to a dict"
        # Convert the list to a dict {name : luid}
        groups_dict = test_site.convert_xml_list_to_name_id_dict(groups_on_site)
        print groups_dict

        sandbox_luid = test_site.query_project_luid_by_name('Sandbox')

        # Change the Sandbox name
        test_site.update_project_by_name('Sandbox', 'Protected Sandbox', 'This is only for important people')

        group_luids = groups_dict.values()

        sandbox_proj = Project(sandbox_luid, test_site, tableau_server_version=tableau_server_version, logger_obj=logger)
        for group_luid in group_luids:
            gcap = GranteeCapabilities(u'group', group_luid, content_type=u'project', tableau_server_version=tableau_server_version)
            if tableau_server_version in [u"9.0", u"9.1"]:
                gcap.set_capability('Read', 'Allow')
                gcap.set_capability('Filter', 'Allow')
                gcap.set_capability('ShareView', 'Allow')
                gcap.set_capability('Delete', 'Allow')
                gcap.set_capability('Write', 'Deny')
                gcap.set_capability('View Underlying Data', 'Deny')
            else:
                gcap.set_capability(u"View", u"Allow")
                gcap.set_capability(u"Save", u"Allow")

                wb_def_gcap = GranteeCapabilities(u'group', group_luid, content_type=u'workbook', tableau_server_version=tableau_server_version)
                wb_def_gcap.set_capabilities_to_match_role(u"Interactor")
                print "Setting default permissions for workbooks on Sandbox project"
                sandbox_proj.workbook_default.set_permissions_by_gcap_obj(wb_def_gcap)
            print 'Updating the permissions on the Sandbox'
            try:
                sandbox_proj.set_permissions_by_gcap_obj(gcap)
            except InvalidOptionException as e:
                print e.msg
                raise

        # Create some fake users to assign to groups
        new_user_luids = []
        for i in range(1, 6):
            username = "user" + str(i)
            full_name = "User {}".format(str(i)) 
            print "Creating User '{}' named '{}'".format(username, full_name)
            new_user_luid = test_site.add_user(username, full_name, 'Interactor', 'password', username + '@nowhere.com')
            print "New User LUID : {}".format(new_user_luid)
            new_user_luids.append(new_user_luid)
        
        for group in groups_dict:
            print "Adding users to group {}".format(group)
            test_site.add_users_to_group_by_luid(new_user_luids, groups_dict.get(group))

        user_1_luid = test_site.query_user_luid_by_username('user1')
        print " User 1 luid: {}".format(user_1_luid)
        # Teardown users
        # Delete all of the users that were just created
        # test_site.remove_users_from_site_by_luid(new_user_luids)

        try:
            project_luid = test_site.query_project_luid_by_name('Protected Sandbox')

            # Publish a datasource to the Sandbox project
            print 'Publishing datasource to Protected Sandbox'
            tde_filename = 'Flights Data.tde'
            tde_content_name = 'Flights Data'
            new_ds_luid = test_site.publish_datasource(tde_filename, tde_content_name, project_luid, True)
            print 'Publishing as {}'.format(new_ds_luid)
            print "Query the datasource"
            ds_xml = test_site.query_datasource_by_luid(new_ds_luid)

            datasources = test_site.query_datasources()

            print 'Publishing TWBX workbook to PRoduction'
            production_luid = test_site.query_project_luid_by_name('Production')
            twbx_filename = 'test_workbook.twbx' # Replace with your own test file
            twbx_content_name = 'Test workbook' # Replace with your own name
            new_wb_luid = test_site.publish_workbook(twbx_filename, twbx_content_name, production_luid, True)
            print 'Moving workbook to Sandbox'
            test_site.update_workbook_by_luid(new_wb_luid, sandbox_luid, show_tabs=True)
            print "querying workbook"
            wb_xml = test_site.query_workbook_by_luid(new_wb_luid)

            # print "Deleting the published DS"
            # test_site.delete_datasources_by_luid(new_ds_luid)

            print "Moving datasource to production"
            test_site.update_datasource_by_luid(new_ds_luid, 'Flites Datums', production_luid)

            print "Query workbook connections"
            wb_connections = test_site.query_workbook_connections_by_luid(new_wb_luid)
            print wb_connections

            print "Querying workbook permissions"
            wb_permissions = test_site.query_workbook_permissions_by_luid(new_wb_luid)
            print wb_permissions

            print "Querying workbook views"
            wb_views = test_site.query_workbook_views_by_luid(new_wb_luid, True)
            print wb_views

            wb_views_dict = test_site.convert_xml_list_to_name_id_dict(wb_views)

            print wb_views_dict

            for wb_view in wb_views_dict:
                print "Adding {} to favorites for me".format(wb_view)
                test_site.add_view_to_user_favorites_by_luid('Fav: {}'.format(wb_view), wb_views_dict.get(wb_view), test_site.query_user_luid_by_username(''))

            for wb_view in wb_views_dict:
                print "Deleting {} to favorites for me".format(wb_view)
                test_site.delete_views_from_user_favorites_by_luid(wb_views_dict.get(wb_view), test_site.query_user_luid_by_username(''))

            # Save workbook preview image
            print "Saving workbook preview image"
            test_site.save_workbook_preview_image_by_luid(new_wb_luid, 'Workbook preview')

            # Saving view as file
            for wb_view in wb_views_dict:
                print "Saving a png for {}".format(wb_view)
                test_site.save_workbook_view_preview_image_by_luid(new_wb_luid, wb_views_dict.get(wb_view), '{}_preview'.format(wb_view))

            print "Saving workbook file"
            test_site.download_workbook_by_luid(new_wb_luid, 'saved workbook')

            print "Saving Datasource"
            test_site.download_datasource_by_luid(new_ds_luid, 'saved_datasource')
            print 'Adding tags to workbook'
            test_site.add_tags_to_workbook_by_luid(new_wb_luid, ['workbooks', 'flights', 'cool'])

            print 'Deleting a tag from workbook'
            test_site.delete_tags_from_workbook_by_luid(new_wb_luid, 'flights')

            print "Add workbook to favorites for me"
            test_site.add_workbook_to_user_favorites_by_luid('My favorite workbook', new_wb_luid, test_site.query_user_luid_by_username(''))

            print "Deleting workbook from favorites for me"
            test_site.delete_workbooks_from_user_favorites_by_luid(new_wb_luid, test_site.query_user_luid_by_username(''))

            # All of these below are just tests of the different files you can upload
            print "Publishing a TWB"
            twb_luid = test_site.publish_workbook('TWB to Publish.twb', 'TWB Publish Test', project_luid)

            print "Downloading TWB"
            test_site.download_workbook_by_luid(twb_luid, 'TWB Save')

            print "Publishing a TDS"
            tds_luid = test_site.publish_datasource('TDS to Publish SS.tds', 'SS TDS', project_luid)

            #print "Publishing TDS with credentials -- reordered args"
            #tds_cred_luid = test_site.publish_datasource('TDS with Credentials.tds', 'TDS w Creds', project_luid, connection_username='postgres', overwrite=True, connection_password='')

            # print "Update Datasource connection"
            # test_site.update_datasource_connection_by_luid(tds_cred_luid, 'localhost', '5432', db_username, db_password)

            print "Saving TDS"
            test_site.download_datasource_by_luid(tds_luid, 'TDS Save')

            #print "Publishing a TDSX"
            #test_site.publish_datasource('TDSX to Publish.tdsx', 'TDSX Publish Test', project_luid)

        except NoMatchFoundException as e:
                print e.msg
        except:
            raise

    except NoMatchFoundException as e:
        print e.msg
    except:
        raise
    
except urllib2.HTTPError as e:
    print e.code
    print e.msg
    print e.hdrs
    print e.fp
except Exception as e:
   raise
