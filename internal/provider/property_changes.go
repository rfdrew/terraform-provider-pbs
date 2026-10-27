package provider

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/rfdrew/terraform-provider-pbs/internal/pbsclient"
)

// A PBS PUT changes only the properties it carries; a property it should
// unset goes by name into the delete parameter instead, and every object has
// its own list of names PBS accepts there. Properties outside that list —
// such as a user's expire — cannot be unset at all: the schema makes them
// Optional and Computed with PBS's default, so that leaving them out of the
// configuration plans that default rather than null.
//
// propertyChanges turns the difference between a plan and the prior state
// into such a PUT: a property whose planned value differs is sent, one the
// plan leaves null although the prior state has it is deleted. A create uses
// it too, with PBS's defaults as the prior values, so that only what differs
// from them is sent.

// propertyChanges collects the parameters of one PUT or POST.
type propertyChanges struct {
	params    url.Values
	deletable map[string]bool
	deletes   []string
	diags     *diag.Diagnostics
}

// newPropertyChanges starts a change of an object whose PUT accepts the given
// names in its delete parameter. Errors — always bugs in the provider — go
// to diags.
func newPropertyChanges(diags *diag.Diagnostics, deletable ...string) *propertyChanges {
	c := &propertyChanges{params: url.Values{}, deletable: map[string]bool{}, diags: diags}
	for _, name := range deletable {
		c.deletable[name] = true
	}
	return c
}

// String, Bool and Int64 record the change of one property, named as PBS
// names it, from prior to plan.
func (c *propertyChanges) String(name string, plan, prior types.String) {
	c.change(name, plan, prior, plan.ValueString)
}

func (c *propertyChanges) Bool(name string, plan, prior types.Bool) {
	c.change(name, plan, prior, func() string { return pbsclient.FormatBool(plan.ValueBool()) })
}

func (c *propertyChanges) Int64(name string, plan, prior types.Int64) {
	c.change(name, plan, prior, func() string { return strconv.FormatInt(plan.ValueInt64(), 10) })
}

func (c *propertyChanges) change(name string, plan, prior attr.Value, format func() string) {
	switch {
	case plan.IsUnknown():
		c.diags.AddError("Unknown planned value",
			fmt.Sprintf("The PBS property %q was still unknown when the change was applied. This is a bug in the provider.", name))
	case plan.Equal(prior):
	case !plan.IsNull():
		c.params.Set(name, format())
	case c.deletable[name]:
		c.deletes = append(c.deletes, name)
	default:
		c.diags.AddError("Property cannot be unset",
			fmt.Sprintf("PBS cannot delete the property %q, so the provider must plan a value for it instead of null. This is a bug in the provider.", name))
	}
}

// Empty reports whether nothing changes.
func (c *propertyChanges) Empty() bool { return len(c.params) == 0 && len(c.deletes) == 0 }

// Values returns the parameters, with the names to delete sorted, so that a
// request is the same from one run to the next.
func (c *propertyChanges) Values() url.Values {
	values := url.Values{}
	for name, v := range c.params {
		values[name] = append([]string(nil), v...)
	}
	pbsclient.AddDelete(values, c.deletes...)
	return values
}
