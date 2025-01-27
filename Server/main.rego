package auth

import rego.v1

# rule to return the resource instances by ids
machines[id] := machine_instance if {
	# iterate the resource instances of some file_instance in data.files
	some machine_instance in data.machines
	id := sprintf("machine:%v",[machine_instance.id])
}

companies[id] := company_instance if {
	# iterate the resource instances of some file_instance in data.files
	some company_instance in data.companies
	id := sprintf("company:%v",[company_instance.id])
}

servicers[id] := service_instance if {
	# iterate the resource instances of some file_instance in data.files
	some service_instance in data.servicers
	id := sprintf("service:%v",[service_instance.id])
}

wrap_in_array(x) := arr if {
    is_array(x)
    arr := x
} else := arr if {
    not is_array(x)
    arr := [x]
}

# return a full graph mapping of each subject to the object it has reference to
full_graph[subject] := ref_object_array if {
    some subject, object_instance in object.union_n([machines, companies, servicers])

    # get the parent_id the subject is referring
    ref_object := object.get(object_instance, "parent", null)

    # Ensure ref_object is always enclosed in exactly one array per item
    ref_object_array := wrap_in_array(ref_object)
}

default allow := false

allow if {
    print("Requested a connection from ", input.userrelation, " to ", input.targetresource, "\n")
    reachable := graph.reachable(full_graph, {input.targetresource})
    print("The following parties can act on behalf of ", input.targetresource, ": ", reachable, "\n")
    input.userrelation in reachable
    print(">>> Allowing the connection <<< \n")
}

