/* THIS CODE IS GENERATED. DON'T CHANGE MANUALLY! */

#include "process.h"
#include "zeek/Val.h"

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-function"

using namespace zeek;

namespace {

template <typename T> inline const T *ptr(const T *v) { return v; }

template <typename T>
inline typename std::enable_if<!std::is_pointer<T>::value, const T *>::type
ptr(const T &v) {
  return &v;
}

inline IntrusivePtr<Val> convert(const int *i) {
  return make_intrusive<IntVal>(*i);
}
inline IntrusivePtr<Val> convert(const long int *i) {
  return make_intrusive<IntVal>(*i);
}
inline IntrusivePtr<Val> convert(const unsigned int *i) {
  return make_intrusive<IntVal>(*i);
}
inline IntrusivePtr<Val> convert(const long unsigned int *i) {
  return make_intrusive<IntVal>(*i);
}

#ifdef _OBJECT_IDENTIFIER_H_
IntrusivePtr<Val> convert(const OBJECT_IDENTIFIER_t *oid) {
  std::string res;
  unsigned long arcs[100];
  int arc_slots = sizeof(arcs) / sizeof(arcs[0]);
  int count = OBJECT_IDENTIFIER_get_arcs(oid, arcs, sizeof(arcs[0]), arc_slots);
  if (count < 0 || count > arc_slots)
    return nullptr;
  for (int i = 0; i < count; i++) {
    if (i != 0)
      res += ".";
    res += std::to_string(arcs[i]);
  }
  return make_intrusive<StringVal>(res);
}
#endif

template <typename T> inline IntrusivePtr<Val> convert(const T *s) {
  return make_intrusive<StringVal>(s->size,
                                   reinterpret_cast<const char *>(s->buf));
}

bool is_bit_set(const BIT_STRING_t *s, unsigned int idx) {
    if (!s || idx >= (unsigned int)(s->size * 8 - s->bits_unused) || s->size <= 0)
        return false;

    unsigned byte_no = idx / 8;
    unsigned bit_no = idx % 8;
    uint8_t byte = s->buf[byte_no];
    // Big-endian: Most significant bit is at position 7, so shift by (7 - bit_no)
    return (byte & (1 << (7 - bit_no))) != 0;
}

/*
 * In the event of an error, the function does not return,
 * but deliberately causes a core dump.
 */
template <typename T>
IntrusivePtr<T> get_field_type(IntrusivePtr<RecordVal> container,
                               const char *fieldname) {
  auto tag = TYPE_RECORD;
  if constexpr (std::is_same_v<T, VectorType>)
    tag = TYPE_VECTOR;
  auto container_type = cast_intrusive<RecordType>(container->GetType());
  if (!container_type->HasField(fieldname)) {
    reporter->InternalError("Unable to process '%s': Missing field '%s'",
                            container_type->GetName().c_str(), fieldname);
  }
  auto field_type = container_type->GetFieldType(fieldname);
  if (field_type->Tag() != tag) {
    reporter->InternalError(
        "Unable to process '%s': Field '%s' is of wrong type",
        container_type->GetName().c_str(), fieldname);
  }
  return cast_intrusive<T>(field_type);
}

template <typename T>
IntrusivePtr<T> get_field_type(IntrusivePtr<VectorVal> container) {
  auto tag = TYPE_RECORD;
  if constexpr (std::is_same_v<T, VectorType>)
    tag = TYPE_VECTOR;
  auto subtype = container->GetType()->Yield();
  if (!subtype || subtype->Tag() != tag) {
    reporter->InternalError("Unable to process '%s': Content is of wrong type",
                            container->GetType()->GetName().c_str());
  }
  return cast_intrusive<T>(subtype);
}
} // namespace

namespace zeek::plugin::acse {

IntrusivePtr<Val> process_Name(const Name_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::Name");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == Name_PR_rdnSequence) {
      const auto _new_src = ptr(src->choice.rdnSequence);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "rdnSequence");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = process_RelativeDistinguishedName(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("rdnSequence", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_RelativeDistinguishedName(const RelativeDistinguishedName_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<VectorType>("acse::RelativeDistinguishedName");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;
      const auto res = process_AttributeTypeAndDistinguishedValue(src);
      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Context(const Context_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::Context");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->contextType);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("contextType", res);
    }

    {
      const auto _new_src = ptr(src->contextValues);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "contextValues");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;
          const auto res = convert(src);
          container->Append(res);
        }
        res = container;
      }

      container->AssignField("contextValues", res);
    }

    {
      const auto default_value = 0;
      const auto _new_src = ptr(src->fallback ? src->fallback : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("fallback", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AttributeTypeAndDistinguishedValue(
    const AttributeTypeAndDistinguishedValue_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("acse::AttributeTypeAndDistinguishedValue");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->type);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("_type", res);
    }

    {
      const auto _new_src = ptr(src->value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("value", res);
    }

    {
      const auto default_value = 1;
      const auto _new_src =
          ptr(src->primaryDistinguished ? src->primaryDistinguished
                                        : &default_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("primaryDistinguished", res);
    }

    if (src->valuesWithContext) {
      const auto _new_src = ptr(src->valuesWithContext);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<VectorType>(container, "valuesWithContext");
        const auto container = make_intrusive<VectorVal>(type);
        for (int i = 0; i < src->list.count; i++) {
          const auto _new_src = src->list.array[i];
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type = get_field_type<RecordType>(container);
            const auto container = make_intrusive<RecordVal>(type);

            if (src->distingAttrValue) {
              const auto _new_src = ptr(src->distingAttrValue);
              const auto src = _new_src;
              const auto res = convert(src);
              container->AssignField("distingAttrValue", res);
            }

            {
              const auto _new_src = ptr(src->contextList);
              const auto src = _new_src;

              IntrusivePtr<Val> res;
              {
                static const auto type =
                    get_field_type<VectorType>(container, "contextList");
                const auto container = make_intrusive<VectorVal>(type);
                for (int i = 0; i < src->list.count; i++) {
                  const auto _new_src = src->list.array[i];
                  const auto src = _new_src;
                  const auto res = process_Context(src);
                  container->Append(res);
                }
                res = container;
              }

              container->AssignField("contextList", res);
            }

            res = container;
          }

          container->Append(res);
        }
        res = container;
      }

      container->AssignField("valuesWithContext", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_EXTERNALt(const EXTERNALt_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::EXTERNALt");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->direct_reference) {
      const auto _new_src = ptr(src->direct_reference);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("direct_reference", res);
    }

    if (src->indirect_reference) {
      const auto _new_src = ptr(src->indirect_reference);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("indirect_reference", res);
    }

    if (src->data_value_descriptor) {
      const auto _new_src = ptr(src->data_value_descriptor);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("data_value_descriptor", res);
    }

    {
      const auto _new_src = ptr(src->encoding);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "encoding");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present == EXTERNALt__encoding_PR_single_ASN1_type) {
          const auto _new_src = ptr(src->choice.single_ASN1_type);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("single_ASN1_type", res);
        }

        if (src->present == EXTERNALt__encoding_PR_octet_aligned) {
          const auto _new_src = ptr(src->choice.octet_aligned);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("octet_aligned", res);
        }

        if (src->present == EXTERNALt__encoding_PR_arbitrary) {
          const auto _new_src = ptr(src->choice.arbitrary);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("arbitrary", res);
        }

        res = container;
      }

      container->AssignField("encoding", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ACSE_apdu(const ACSE_apdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::ACSE_apdu");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == ACSE_apdu_PR_aarq) {
      const auto _new_src = ptr(src->choice.aarq);
      const auto src = _new_src;
      const auto res = process_AARQ_apdu(src);
      container->AssignField("aarq", res);
    }

    if (src->present == ACSE_apdu_PR_aare) {
      const auto _new_src = ptr(src->choice.aare);
      const auto src = _new_src;
      const auto res = process_AARE_apdu(src);
      container->AssignField("aare", res);
    }

    if (src->present == ACSE_apdu_PR_rlrq) {
      const auto _new_src = ptr(src->choice.rlrq);
      const auto src = _new_src;
      const auto res = process_RLRQ_apdu(src);
      container->AssignField("rlrq", res);
    }

    if (src->present == ACSE_apdu_PR_rlre) {
      const auto _new_src = ptr(src->choice.rlre);
      const auto src = _new_src;
      const auto res = process_RLRE_apdu(src);
      container->AssignField("rlre", res);
    }

    if (src->present == ACSE_apdu_PR_abrt) {
      const auto _new_src = ptr(src->choice.abrt);
      const auto src = _new_src;
      const auto res = process_ABRT_apdu(src);
      container->AssignField("abrt", res);
    }

    if (src->present == ACSE_apdu_PR_adt) {
      const auto _new_src = ptr(src->choice.adt);
      const auto src = _new_src;
      const auto res = process_A_DT_apdu(src);
      container->AssignField("adt", res);
    }

    if (src->present == ACSE_apdu_PR_acrq) {
      const auto _new_src = ptr(src->choice.acrq);
      const auto src = _new_src;
      const auto res = process_ACRQ_apdu(src);
      container->AssignField("acrq", res);
    }

    if (src->present == ACSE_apdu_PR_acrp) {
      const auto _new_src = ptr(src->choice.acrp);
      const auto src = _new_src;
      const auto res = process_ACRP_apdu(src);
      container->AssignField("acrp", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AARQ_apdu(const AARQ_apdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::AARQ_apdu");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->protocol_version);
      const auto src = _new_src;
      static const auto type =
          get_field_type<VectorType>(container, "protocol_version");
      static IntrusivePtr<EnumType> enum_type = nullptr;
      if (!enum_type) {
        auto subtype = type->Yield();
        if (!subtype || subtype->Tag() != TYPE_ENUM)
          reporter->InternalError(
              "Unable to process 'AARQ-apdu__protocol-version': "
              "%s is not a vector of enums",
              type->GetName().c_str());
        enum_type = cast_intrusive<EnumType>(subtype);
      }
      auto res = make_intrusive<VectorVal>(type);
      if (src ? is_bit_set(src, 0) : true) /* version1 */
        res->Append(enum_type->GetEnumVal(0));

      container->AssignField("protocol_version", res);
    }

    {
      const auto _new_src = ptr(src->aSO_context_name);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("aSO_context_name", res);
    }

    if (src->called_AP_title) {
      const auto _new_src = ptr(src->called_AP_title);
      const auto src = _new_src;
      const auto res = process_AP_title(src);
      container->AssignField("called_AP_title", res);
    }

    if (src->called_AE_qualifier) {
      const auto _new_src = ptr(src->called_AE_qualifier);
      const auto src = _new_src;
      const auto res = process_ASO_qualifier(src);
      container->AssignField("called_AE_qualifier", res);
    }

    if (src->called_AP_invocation_identifier) {
      const auto _new_src = ptr(src->called_AP_invocation_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("called_AP_invocation_identifier", res);
    }

    if (src->called_AE_invocation_identifier) {
      const auto _new_src = ptr(src->called_AE_invocation_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("called_AE_invocation_identifier", res);
    }

    if (src->calling_AP_title) {
      const auto _new_src = ptr(src->calling_AP_title);
      const auto src = _new_src;
      const auto res = process_AP_title(src);
      container->AssignField("calling_AP_title", res);
    }

    if (src->calling_AE_qualifier) {
      const auto _new_src = ptr(src->calling_AE_qualifier);
      const auto src = _new_src;
      const auto res = process_ASO_qualifier(src);
      container->AssignField("calling_AE_qualifier", res);
    }

    if (src->calling_AP_invocation_identifier) {
      const auto _new_src = ptr(src->calling_AP_invocation_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("calling_AP_invocation_identifier", res);
    }

    if (src->calling_AE_invocation_identifier) {
      const auto _new_src = ptr(src->calling_AE_invocation_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("calling_AE_invocation_identifier", res);
    }

    if (src->sender_acse_requirements) {
      const auto _new_src = ptr(src->sender_acse_requirements);
      const auto src = _new_src;
      const auto res = process_ACSE_requirements(src);
      container->AssignField("sender_acse_requirements", res);
    }

    if (src->mechanism_name) {
      const auto _new_src = ptr(src->mechanism_name);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mechanism_name", res);
    }

    if (src->calling_authentication_value) {
      const auto _new_src = ptr(src->calling_authentication_value);
      const auto src = _new_src;
      const auto res = process_Authentication_value(src);
      container->AssignField("calling_authentication_value", res);
    }

    if (src->aSO_context_name_list) {
      const auto _new_src = ptr(src->aSO_context_name_list);
      const auto src = _new_src;
      const auto res = process_ASO_context_name_list(src);
      container->AssignField("aSO_context_name_list", res);
    }

    if (src->implementation_information) {
      const auto _new_src = ptr(src->implementation_information);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("implementation_information", res);
    }

    if (src->p_context_definition_list) {
      const auto _new_src = ptr(src->p_context_definition_list);
      const auto src = _new_src;
      const auto res = process_Syntactic_context_list(src);
      container->AssignField("p_context_definition_list", res);
    }

    if (src->called_asoi_tag) {
      const auto _new_src = ptr(src->called_asoi_tag);
      const auto src = _new_src;
      const auto res = process_ASOI_tag(src);
      container->AssignField("called_asoi_tag", res);
    }

    if (src->calling_asoi_tag) {
      const auto _new_src = ptr(src->calling_asoi_tag);
      const auto src = _new_src;
      const auto res = process_ASOI_tag(src);
      container->AssignField("calling_asoi_tag", res);
    }

    if (src->user_information) {
      const auto _new_src = ptr(src->user_information);
      const auto src = _new_src;
      const auto res = process_Association_data(src);
      container->AssignField("user_information", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AARE_apdu(const AARE_apdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::AARE_apdu");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->protocol_version);
      const auto src = _new_src;
      static const auto type =
          get_field_type<VectorType>(container, "protocol_version");
      static IntrusivePtr<EnumType> enum_type = nullptr;
      if (!enum_type) {
        auto subtype = type->Yield();
        if (!subtype || subtype->Tag() != TYPE_ENUM)
          reporter->InternalError(
              "Unable to process 'AARE-apdu__protocol-version': "
              "%s is not a vector of enums",
              type->GetName().c_str());
        enum_type = cast_intrusive<EnumType>(subtype);
      }
      auto res = make_intrusive<VectorVal>(type);
      if (src ? is_bit_set(src, 0) : true) /* version1 */
        res->Append(enum_type->GetEnumVal(0));

      container->AssignField("protocol_version", res);
    }

    {
      const auto _new_src = ptr(src->aSO_context_name);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("aSO_context_name", res);
    }

    {
      const auto _new_src = ptr(src->result);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("result", res);
    }

    {
      const auto _new_src = ptr(src->result_source_diagnostic);
      const auto src = _new_src;
      const auto res = process_Associate_source_diagnostic(src);
      container->AssignField("result_source_diagnostic", res);
    }

    if (src->responding_AP_title) {
      const auto _new_src = ptr(src->responding_AP_title);
      const auto src = _new_src;
      const auto res = process_AP_title(src);
      container->AssignField("responding_AP_title", res);
    }

    if (src->responding_AE_qualifier) {
      const auto _new_src = ptr(src->responding_AE_qualifier);
      const auto src = _new_src;
      const auto res = process_ASO_qualifier(src);
      container->AssignField("responding_AE_qualifier", res);
    }

    if (src->responding_AP_invocation_identifier) {
      const auto _new_src = ptr(src->responding_AP_invocation_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("responding_AP_invocation_identifier", res);
    }

    if (src->responding_AE_invocation_identifier) {
      const auto _new_src = ptr(src->responding_AE_invocation_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("responding_AE_invocation_identifier", res);
    }

    if (src->responder_acse_requirements) {
      const auto _new_src = ptr(src->responder_acse_requirements);
      const auto src = _new_src;
      const auto res = process_ACSE_requirements(src);
      container->AssignField("responder_acse_requirements", res);
    }

    if (src->mechanism_name) {
      const auto _new_src = ptr(src->mechanism_name);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("mechanism_name", res);
    }

    if (src->responding_authentication_value) {
      const auto _new_src = ptr(src->responding_authentication_value);
      const auto src = _new_src;
      const auto res = process_Authentication_value(src);
      container->AssignField("responding_authentication_value", res);
    }

    if (src->aSO_context_name_list) {
      const auto _new_src = ptr(src->aSO_context_name_list);
      const auto src = _new_src;
      const auto res = process_ASO_context_name_list(src);
      container->AssignField("aSO_context_name_list", res);
    }

    if (src->implementation_information) {
      const auto _new_src = ptr(src->implementation_information);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("implementation_information", res);
    }

    if (src->p_context_result_list) {
      const auto _new_src = ptr(src->p_context_result_list);
      const auto src = _new_src;
      const auto res = process_P_context_result_list(src);
      container->AssignField("p_context_result_list", res);
    }

    if (src->called_asoi_tag) {
      const auto _new_src = ptr(src->called_asoi_tag);
      const auto src = _new_src;
      const auto res = process_ASOI_tag(src);
      container->AssignField("called_asoi_tag", res);
    }

    if (src->calling_asoi_tag) {
      const auto _new_src = ptr(src->calling_asoi_tag);
      const auto src = _new_src;
      const auto res = process_ASOI_tag(src);
      container->AssignField("calling_asoi_tag", res);
    }

    if (src->user_information) {
      const auto _new_src = ptr(src->user_information);
      const auto src = _new_src;
      const auto res = process_Association_data(src);
      container->AssignField("user_information", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_RLRQ_apdu(const RLRQ_apdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::RLRQ_apdu");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->reason) {
      const auto _new_src = ptr(src->reason);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("reason", res);
    }

    if (src->aso_qualifier) {
      const auto _new_src = ptr(src->aso_qualifier);
      const auto src = _new_src;
      const auto res = process_ASO_qualifier(src);
      container->AssignField("aso_qualifier", res);
    }

    if (src->asoi_identifier) {
      const auto _new_src = ptr(src->asoi_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("asoi_identifier", res);
    }

    if (src->user_information) {
      const auto _new_src = ptr(src->user_information);
      const auto src = _new_src;
      const auto res = process_Association_data(src);
      container->AssignField("user_information", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_RLRE_apdu(const RLRE_apdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::RLRE_apdu");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->reason) {
      const auto _new_src = ptr(src->reason);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("reason", res);
    }

    if (src->aso_qualifier) {
      const auto _new_src = ptr(src->aso_qualifier);
      const auto src = _new_src;
      const auto res = process_ASO_qualifier(src);
      container->AssignField("aso_qualifier", res);
    }

    if (src->asoi_identifier) {
      const auto _new_src = ptr(src->asoi_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("asoi_identifier", res);
    }

    if (src->user_information) {
      const auto _new_src = ptr(src->user_information);
      const auto src = _new_src;
      const auto res = process_Association_data(src);
      container->AssignField("user_information", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ABRT_apdu(const ABRT_apdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::ABRT_apdu");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->abort_source);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("abort_source", res);
    }

    if (src->abort_diagnostic) {
      const auto _new_src = ptr(src->abort_diagnostic);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("abort_diagnostic", res);
    }

    if (src->aso_qualifier) {
      const auto _new_src = ptr(src->aso_qualifier);
      const auto src = _new_src;
      const auto res = process_ASO_qualifier(src);
      container->AssignField("aso_qualifier", res);
    }

    if (src->asoi_identifier) {
      const auto _new_src = ptr(src->asoi_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("asoi_identifier", res);
    }

    if (src->user_information) {
      const auto _new_src = ptr(src->user_information);
      const auto src = _new_src;
      const auto res = process_Association_data(src);
      container->AssignField("user_information", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_A_DT_apdu(const A_DT_apdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::A_DT_apdu");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->aso_qualifier) {
      const auto _new_src = ptr(src->aso_qualifier);
      const auto src = _new_src;
      const auto res = process_ASO_qualifier(src);
      container->AssignField("aso_qualifier", res);
    }

    if (src->asoi_identifier) {
      const auto _new_src = ptr(src->asoi_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("asoi_identifier", res);
    }

    {
      const auto _new_src = ptr(src->a_user_data);
      const auto src = _new_src;
      const auto res = process_User_Data(src);
      container->AssignField("a_user_data", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ACRQ_apdu(const ACRQ_apdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::ACRQ_apdu");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->aso_qualifier) {
      const auto _new_src = ptr(src->aso_qualifier);
      const auto src = _new_src;
      const auto res = process_ASO_qualifier(src);
      container->AssignField("aso_qualifier", res);
    }

    if (src->asoi_identifier) {
      const auto _new_src = ptr(src->asoi_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("asoi_identifier", res);
    }

    if (src->aSO_context_name) {
      const auto _new_src = ptr(src->aSO_context_name);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("aSO_context_name", res);
    }

    if (src->aSO_context_name_list) {
      const auto _new_src = ptr(src->aSO_context_name_list);
      const auto src = _new_src;
      const auto res = process_ASO_context_name_list(src);
      container->AssignField("aSO_context_name_list", res);
    }

    if (src->p_context_definition_list) {
      const auto _new_src = ptr(src->p_context_definition_list);
      const auto src = _new_src;
      const auto res = process_Syntactic_context_list(src);
      container->AssignField("p_context_definition_list", res);
    }

    if (src->user_information) {
      const auto _new_src = ptr(src->user_information);
      const auto src = _new_src;
      const auto res = process_Association_data(src);
      container->AssignField("user_information", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ACRP_apdu(const ACRP_apdu_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::ACRP_apdu");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->aso_qualifier) {
      const auto _new_src = ptr(src->aso_qualifier);
      const auto src = _new_src;
      const auto res = process_ASO_qualifier(src);
      container->AssignField("aso_qualifier", res);
    }

    if (src->asoi_identifier) {
      const auto _new_src = ptr(src->asoi_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("asoi_identifier", res);
    }

    if (src->aSO_context_name) {
      const auto _new_src = ptr(src->aSO_context_name);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("aSO_context_name", res);
    }

    if (src->p_context_result_list) {
      const auto _new_src = ptr(src->p_context_result_list);
      const auto src = _new_src;
      const auto res = process_P_context_result_list(src);
      container->AssignField("p_context_result_list", res);
    }

    if (src->user_information) {
      const auto _new_src = ptr(src->user_information);
      const auto src = _new_src;
      const auto res = process_Association_data(src);
      container->AssignField("user_information", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_ACSE_requirements(const ACSE_requirements_t *src) {
  static const auto type = id::find_type<VectorType>("acse::ACSE_requirements");
  static IntrusivePtr<EnumType> enum_type = nullptr;
  if (!enum_type) {
    auto subtype = type->Yield();
    if (!subtype || subtype->Tag() != TYPE_ENUM)
      reporter->InternalError("Unable to process 'ACSE-requirements': "
                              "%s is not a vector of enums",
                              type->GetName().c_str());
    enum_type = cast_intrusive<EnumType>(subtype);
  }
  auto res = make_intrusive<VectorVal>(type);
  if (src ? is_bit_set(src, 0) : false) /* authentication */
    res->Append(enum_type->GetEnumVal(0));
  if (src ? is_bit_set(src, 1) : false) /* aSO-context-negotiation */
    res->Append(enum_type->GetEnumVal(1));
  if (src ? is_bit_set(src, 2) : false) /* higher-level-association */
    res->Append(enum_type->GetEnumVal(2));
  if (src ? is_bit_set(src, 3) : false) /* nested-association */
    res->Append(enum_type->GetEnumVal(3));
  return res;
}

IntrusivePtr<Val>
process_Application_context_name(const Application_context_name_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val> process_AP_title(const AP_title_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::AP_title");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == AP_title_PR_ap_title_form1) {
      const auto _new_src = ptr(src->choice.ap_title_form1);
      const auto src = _new_src;
      const auto res = process_Name(src);
      container->AssignField("ap_title_form1", res);
    }

    if (src->present == AP_title_PR_ap_title_form2) {
      const auto _new_src = ptr(src->choice.ap_title_form2);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("ap_title_form2", res);
    }

    if (src->present == AP_title_PR_ap_title_form3) {
      const auto _new_src = ptr(src->choice.ap_title_form3);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("ap_title_form3", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AE_qualifier(const AE_qualifier_t *src) {
  const auto res = process_ASO_qualifier(src);
  return res;
}

IntrusivePtr<Val> process_ASO_qualifier(const ASO_qualifier_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::ASO_qualifier");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == ASO_qualifier_PR_aso_qualifier_form1) {
      const auto _new_src = ptr(src->choice.aso_qualifier_form1);
      const auto src = _new_src;
      const auto res = process_RelativeDistinguishedName(src);
      container->AssignField("aso_qualifier_form1", res);
    }

    if (src->present == ASO_qualifier_PR_aso_qualifier_form2) {
      const auto _new_src = ptr(src->choice.aso_qualifier_form2);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("aso_qualifier_form2", res);
    }

    if (src->present == ASO_qualifier_PR_aso_qualifier_form3) {
      const auto _new_src = ptr(src->choice.aso_qualifier_form3);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("aso_qualifier_form3", res);
    }

    if (src->present == ASO_qualifier_PR_aso_qualifier_form_any_octets) {
      const auto _new_src = ptr(src->choice.aso_qualifier_form_any_octets);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("aso_qualifier_form_any_octets", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AP_title_form1(const AP_title_form1_t *src) {
  const auto res = process_Name(src);
  return res;
}

IntrusivePtr<Val>
process_ASO_qualifier_form1(const ASO_qualifier_form1_t *src) {
  const auto res = process_RelativeDistinguishedName(src);
  return res;
}

IntrusivePtr<Val> process_AE_title(const AE_title_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::AE_title");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == AE_title_PR_ae_title_form1) {
      const auto _new_src = ptr(src->choice.ae_title_form1);
      const auto src = _new_src;
      const auto res = process_Name(src);
      container->AssignField("ae_title_form1", res);
    }

    if (src->present == AE_title_PR_ae_title_form2) {
      const auto _new_src = ptr(src->choice.ae_title_form2);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("ae_title_form2", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_AE_title_form1(const AE_title_form1_t *src) {
  const auto res = process_Name(src);
  return res;
}

IntrusivePtr<Val> process_ASOI_tag(const ASOI_tag_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<VectorType>("acse::ASOI_tag");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<RecordType>(container);
        const auto container = make_intrusive<RecordVal>(type);

        if (src->qualifier) {
          const auto _new_src = ptr(src->qualifier);
          const auto src = _new_src;
          const auto res = process_ASO_qualifier(src);
          container->AssignField("qualifier", res);
        }

        if (src->identifier) {
          const auto _new_src = ptr(src->identifier);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("identifier", res);
        }

        res = container;
      }

      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_ASO_context_name_list(const ASO_context_name_list_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<VectorType>("acse::ASO_context_name_list");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;
      const auto res = convert(src);
      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_Syntactic_context_list(const Syntactic_context_list_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("acse::Syntactic_context_list");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == Syntactic_context_list_PR_context_list) {
      const auto _new_src = ptr(src->choice.context_list);
      const auto src = _new_src;
      const auto res = process_Context_list(src);
      container->AssignField("context_list", res);
    }

    if (src->present == Syntactic_context_list_PR_default_contact_list) {
      const auto _new_src = ptr(src->choice.default_contact_list);
      const auto src = _new_src;
      const auto res = process_Default_Context_List(src);
      container->AssignField("default_contact_list", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_Context_list(const Context_list_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<VectorType>("acse::Context_list");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<RecordType>(container);
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->pci);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("pci", res);
        }

        {
          const auto _new_src = ptr(src->abstract_syntax);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("abstract_syntax", res);
        }

        {
          const auto _new_src = ptr(src->transfer_syntaxes);
          const auto src = _new_src;

          IntrusivePtr<Val> res;
          {
            static const auto type =
                get_field_type<VectorType>(container, "transfer_syntaxes");
            const auto container = make_intrusive<VectorVal>(type);
            for (int i = 0; i < src->list.count; i++) {
              const auto _new_src = src->list.array[i];
              const auto src = _new_src;
              const auto res = convert(src);
              container->Append(res);
            }
            res = container;
          }

          container->AssignField("transfer_syntaxes", res);
        }

        res = container;
      }

      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_Default_Context_List(const Default_Context_List_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<VectorType>("acse::Default_Context_List");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<RecordType>(container);
        const auto container = make_intrusive<RecordVal>(type);

        if (src->abstract_syntax_name) {
          const auto _new_src = ptr(src->abstract_syntax_name);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("abstract_syntax_name", res);
        }

        {
          const auto _new_src = ptr(src->transfer_syntax_name);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("transfer_syntax_name", res);
        }

        res = container;
      }

      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_P_context_result_list(const P_context_result_list_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<VectorType>("acse::P_context_result_list");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type = get_field_type<RecordType>(container);
        const auto container = make_intrusive<RecordVal>(type);

        {
          const auto _new_src = ptr(src->result);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("result", res);
        }

        if (src->concrete_syntax_name) {
          const auto _new_src = ptr(src->concrete_syntax_name);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("concrete_syntax_name", res);
        }

        if (src->provider_reason) {
          const auto _new_src = ptr(src->provider_reason);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("provider_reason", res);
        }

        res = container;
      }

      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_Concrete_syntax_name(const Concrete_syntax_name_t *src) {
  const auto res = convert(src);
  return res;
}

IntrusivePtr<Val>
process_Associate_source_diagnostic(const Associate_source_diagnostic_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("acse::Associate_source_diagnostic");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == Associate_source_diagnostic_PR_service_user) {
      const auto _new_src = ptr(src->choice.service_user);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("service_user", res);
    }

    if (src->present == Associate_source_diagnostic_PR_service_provider) {
      const auto _new_src = ptr(src->choice.service_provider);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("service_provider", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_User_information(const User_information_t *src) {
  const auto res = process_Association_data(src);
  return res;
}

IntrusivePtr<Val> process_Association_data(const Association_data_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<VectorType>("acse::Association_data");
    const auto container = make_intrusive<VectorVal>(type);
    for (int i = 0; i < src->list.count; i++) {
      const auto _new_src = src->list.array[i];
      const auto src = _new_src;
      const auto res = process_EXTERNALt(src);
      container->Append(res);
    }
    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_User_Data(const User_Data_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::User_Data");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == User_Data_PR_user_information) {
      const auto _new_src = ptr(src->choice.user_information);
      const auto src = _new_src;
      const auto res = process_Association_data(src);
      container->AssignField("user_information", res);
    }

    if (src->present == User_Data_PR_simply_encoded_data) {
      const auto _new_src = ptr(src->choice.simply_encoded_data);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("simply_encoded_data", res);
    }

    if (src->present == User_Data_PR_fully_encoded_data) {
      const auto _new_src = ptr(src->choice.fully_encoded_data);
      const auto src = _new_src;
      const auto res = process_PDV_list(src);
      container->AssignField("fully_encoded_data", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val> process_PDV_list(const PDV_list_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type = id::find_type<RecordType>("acse::PDV_list");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->transfer_syntax_name) {
      const auto _new_src = ptr(src->transfer_syntax_name);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("transfer_syntax_name", res);
    }

    {
      const auto _new_src = ptr(src->presentation_context_identifier);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("presentation_context_identifier", res);
    }

    {
      const auto _new_src = ptr(src->presentation_data_values);
      const auto src = _new_src;

      IntrusivePtr<Val> res;
      {
        static const auto type =
            get_field_type<RecordType>(container, "presentation_data_values");
        const auto container = make_intrusive<RecordVal>(type);

        if (src->present ==
            PDV_list__presentation_data_values_PR_simple_ASN1_type) {
          const auto _new_src = ptr(src->choice.simple_ASN1_type);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("simple_ASN1_type", res);
        }

        if (src->present ==
            PDV_list__presentation_data_values_PR_octet_aligned) {
          const auto _new_src = ptr(src->choice.octet_aligned);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("octet_aligned", res);
        }

        if (src->present == PDV_list__presentation_data_values_PR_arbitrary) {
          const auto _new_src = ptr(src->choice.arbitrary);
          const auto src = _new_src;
          const auto res = convert(src);
          container->AssignField("arbitrary", res);
        }

        res = container;
      }

      container->AssignField("presentation_data_values", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_Authentication_value_other(const Authentication_value_other_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("acse::Authentication_value_other");
    const auto container = make_intrusive<RecordVal>(type);

    {
      const auto _new_src = ptr(src->other_mechanism_name);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("other_mechanism_name", res);
    }

    {
      const auto _new_src = ptr(src->other_mechanism_value);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("other_mechanism_value", res);
    }

    res = container;
  }
  return res;
}

IntrusivePtr<Val>
process_Authentication_value(const Authentication_value_t *src) {
  IntrusivePtr<Val> res;
  {
    static const auto type =
        id::find_type<RecordType>("acse::Authentication_value");
    const auto container = make_intrusive<RecordVal>(type);

    if (src->present == Authentication_value_PR_charstring) {
      const auto _new_src = ptr(src->choice.charstring);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("charstring", res);
    }

    if (src->present == Authentication_value_PR_bitstring) {
      const auto _new_src = ptr(src->choice.bitstring);
      const auto src = _new_src;
      const auto res = convert(src);
      container->AssignField("bitstring", res);
    }

    if (src->present == Authentication_value_PR_external) {
      const auto _new_src = ptr(src->choice.external);
      const auto src = _new_src;
      const auto res = process_EXTERNALt(src);
      container->AssignField("external", res);
    }

    if (src->present == Authentication_value_PR_other) {
      const auto _new_src = ptr(src->choice.other);
      const auto src = _new_src;
      const auto res = process_Authentication_value_other(src);
      container->AssignField("other", res);
    }

    res = container;
  }
  return res;
}

} // namespace zeek::plugin::acse
