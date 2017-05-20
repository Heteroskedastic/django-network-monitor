String.prototype.format = String.prototype.f = function() {
    var s = this,
        i = arguments.length;

    while (i--) {
        s = s.replace(new RegExp('\\{' + i + '\\}', 'gm'), arguments[i]);
    }
    return s;
};

function togglablePassword(selector, dataPos) {
    var blurChars = '••••••••';
    $(selector).each(function (i, el) {
        var $eye_el = $(el).addClass('fa fa-eye').attr('title', 'Show'),
            $data_el = dataPos=='prev'? $eye_el.prev(): $eye_el.next();
        $data_el.attr('data-value', $data_el.text()).text(blurChars);
        $eye_el.click(function () {
            if ($eye_el.hasClass('fa-eye')) {
                $eye_el.removeClass('fa-eye').addClass('fa-eye-slash text-danger').attr('title', 'Hide');
                $data_el.text($data_el.attr('data-value') || 'N/A')
            } else {
                $eye_el.removeClass('fa-eye-slash text-danger').addClass('fa-eye').attr('title', 'Show');
                $data_el.text(blurChars)
            }
        });
    })
}

function bindModalAction(modalId, actionName, title, message, action) {
    $('button[name={0}]'.f(actionName)).click(function(e) {
        e.preventDefault();
        var form = $('#{0} form'.f(modalId));
        if(action) {
            var id = $(this).parents('tr').attr('data-id');
            form[0].action = action.slice(0, -2) + id + '/';
        }
        if(title) {
            $('#{0} .modal-title'.f(modalId)).text(title);
        }
        if(message) {
            $('#{0} .modal-body'.f(modalId)).text(message);
        }
        $('#{0}'.f(modalId)).modal('show');
    });
}
