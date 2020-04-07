dock_plist = "/Users/tsmith/Library/Preferences/com.apple.dock.plist"

plist "put the Dock on the right side" do
  path dock_plist
  entry "orientation"
  value "right"
  owner "tsmith"
  group "staff"
end
