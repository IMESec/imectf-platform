$("#flag-submission").click(function() {
	var flag = $("#flag-input").val();

	var tid = $("#task-id").val()
	var comp_id = $("#comp-id").val()

    $.ajax({
        url: "/submit/" + comp_id + "/" + tid + "/" + btoa(flag)
    }).done(function(data) {

        console.log(data);

        if (data["success"]) {
            $("#flag-input").val($(".lang").data("success"));
            $("#flag-submission").removeClass("btn-primary");
            $("#flag-submission").addClass("btn-success");
            $("#flag-submission").attr('disabled','disabled');
        } else {
            $("#flag-input").val($(".lang").data("failure"));
        }
    });
});
