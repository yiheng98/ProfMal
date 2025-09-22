from __future__ import annotations

import copy


class Object:
    def __init__(self, name, object_type, source_pdg: int | None, ref_count=0):
        self.object_name = name  # Object name, not really used, just for debug convenience
        self.object_type = object_type  # Identifier type: OBJECT, GLOBAL OBJECT
        self.source_pdg = source_pdg  # Which PDG this belongs to
        self.full_name = name  # full name of the object
        self.property_dict = {}  # record the full to the property
        self.ref_count = ref_count  # Record the number of times this object is referenced

    def get_name(self):
        return self.object_name

    def get_object_type(self):
        return self.object_type

    def set_object_type(self, object_type):
        self.object_type = object_type

    def get_pdg(self):
        return self.source_pdg

    def set_full_name(self, object_full_name):
        self.full_name = object_full_name

    def get_full_name(self):
        return self.full_name

    def add_ref_count(self):
        self.ref_count += 1

    def subtract_ref_count(self):
        self.ref_count -= 1

    def get_ref_count(self):
        return self.ref_count

    def set_property(self, property_name, target):
        if property_name:
            self.property_dict[property_name] = target

    def resolve(self, property_list):
        """
        based on the property find the latest object and property_list
        """
        current_object = self
        for i in range(1, len(property_list) + 1):
            property_str = ".".join(property_list[:i])
            if property_str in current_object.property_dict:
                property_value = current_object.property_dict[property_str]
                if isinstance(property_value, Object):
                    # current value is object
                    if len(property_list[i:]) == 1:
                        return property_value, property_list[i:]
                    else:
                        return property_value.resolve(property_list[i:])
                else:
                    continue
        return current_object, property_list

    def get_property_actual_value(self, property_list):
        if not property_list or len(property_list) == 0:
            return self

        full_name = None
        for i in range(1, len(property_list) + 1):
            current_property = ".".join(property_list[:i])
            if current_property in self.property_dict:
                property_value = self.property_dict[current_property]
                if isinstance(property_value, Object):
                    # current value is object
                    full_name = property_value.get_property_actual_value(property_list[i:])
                elif property_value is None:
                    continue
                else:
                    full_name = self.property_dict[current_property] + ".".join(property_list[i:])
        if full_name is None:
            if self.full_name is not None:
                return f"{self.full_name}.{'.'.join(property_list)}"
            else:
                return None
        else:
            return full_name

    def __repr__(self):
        return (
            f"Object(name={self.object_name!r}, object_type={self.object_type!r}, "
            f"full_name={self.full_name!r}, property_dict={self.property_dict!r})"
        )
